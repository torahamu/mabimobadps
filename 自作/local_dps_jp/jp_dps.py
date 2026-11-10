"""Mabinogi Mobile Japan: passive damage-event prototype.

Offline PCAPNG parsing uses Python's standard library only.
Live capture needs scapy/Npcap and websockets; game traffic is only read, not modified.
Source is intentionally self-contained and makes no outbound connections.
Protocol identified empirically in a two 2026-10-16 captures; not an official API.
"""
from __future__ import annotations

import argparse
import collections
import csv
from dataclasses import dataclass
import datetime as dt
import ipaddress
import logging
import queue
import struct
import threading
import time
from pathlib import Path

LOGGER = logging.getLogger("jp_dps")
FRAME_HEADER = b"\x43\x52\x00\x00\x35\x00\x00\x00\x00"  # type=0x5243, len=53, codec=0
PAYLOAD_LEN = 53
# Optional 0x5241 (29-byte) combat-result record can occur between
# damage 0x5243 and associated effect 0x4FF7 (confirmed on JP 2026-11-03).
AUX_HEADER = b"\x41\x52\x00\x00\x1d\x00\x00\x00\x00"
EFFECT_HEADER = b"\xf7\x4f\x00\x00\x23\x00\x00\x00\x00"
JST = dt.timezone(dt.timedelta(hours=9))

try:
    from .skill_catalog import get_catalog
    from .damage_labels import unassigned_label, flag_details, attribute_label, evidence as flag_evidence
except ImportError:  # direct execution: python local_dps_jp/jp_dps.py
    from skill_catalog import get_catalog
    from damage_labels import unassigned_label, flag_details, attribute_label, evidence as flag_evidence


# Derived from the 2026-10-30 JP practice-dummy capture.  These are
# damage-effect identifiers in 0x4FF7, not proven persistent skill IDs.
# Naming direct hits is high confidence; proc/DoT attribution is tentative.
EFFECT_NAMES = {
    0x0B656FA2: "IceMage_CrystalEdge_01 / クリスタルエッジ①",
    0x4DFF3831: "IceMage_CrystalEdge_02 / クリスタルエッジ②",
    0x7E51D8A1: "IceMage_CrystalEdge_03 / クリスタルエッジ③",
    0x772815F3: "IceMage_通常攻撃（検証一致）",
    0x2972020F: "IceMage_CrystalEdge_Tier2A / クリスタルソード直接ヒット",
    0x240EEC7C: "IceMage_氷追加ヒット候補（未確定）",
    0x5BC5DB35: "IceMage_継続ダメージ候補（未確定）",
}
# The bit positions come from the original Korean mobi_capture.py FLAG_BITS.
# CRIT/UNGUARDED/BREAK/POWER/FAST agree with the JP screenshot examples.
FLAG_BITS = [
    (0,"crit",0x01),(0,"unguarded",0x04),(0,"break",0x08),
    (0,"first_hit",0x40),(0,"default_attack",0x80),
    (1,"multi_attack",0x01),(1,"power",0x02),(1,"fast",0x04),
    (1,"dot",0x08),(3,"add_hit",0x08),(3,"bleed",0x10),
    (3,"fire",0x40),(3,"holy",0x80),(4,"ice",0x01),
    (4,"electric",0x02),(4,"poison",0x04),(4,"mind",0x08),
    (4,"not_dot",0x10),
]

def parse_flags(flags: bytes) -> dict[str, int]:
    return {name: int(bool(flags[index] & mask)) for index, name, mask in FLAG_BITS}

@dataclass(frozen=True)
class Event:
    timestamp: float
    source: int
    target: int
    damage: int
    effect_id: int | None = None
    flag_bytes: bytes = b"\x00" * 6
    effect_linkage: str = ""  # direct / via_0x5241 / missing

    @property
    def skill_name(self):
        # Split effect-id-zero or absent DoTs by actual attributes; do not
        # claim a specific rune, buff, or spell from an attribute bit alone.
        special = unassigned_label(self.effect_id, self.flag_bytes)
        if special:
            return special
        try:
            catalog = get_catalog()
            entry = catalog.get(self.effect_id)
            if entry:
                if entry.is_player:
                    return entry.display
                high_alias = catalog.high_alias_for(self.effect_id)
                if high_alias:
                    return f"{high_alias.display}（High系別ID・名称候補）"
                # The broad dictionary marks HighHealer as "not player" despite
                # matching actual JP Healer action logs.  Show its literal
                # internal name, explicitly NOT a verified Japanese skill name.
                if entry.symbol:
                    tag = f"・{attribute_label(self.flag_bytes)}DoT" if flag_details(self.flag_bytes)["is_dot"] else ""
                    return f"{entry.symbol}（辞書内名・未照合{tag}）"
            # The JP effect field is uint64; several hit IDs have two nonzero
            # halves. Matching the lower 32 bits is a HYPOTHESIS ONLY.
            if self.effect_id is not None and self.effect_id > 0xFFFFFFFF:
                lower_id = self.effect_id & 0xFFFFFFFF
                lower = catalog.get(lower_id)
                low_alias = catalog.high_alias_for(lower_id)
                if low_alias:
                    return f"{low_alias.display}（複合ID下位32bit＋High系名候補・未検証）"
                if lower and lower.symbol:
                    return f"{lower.symbol}（複合ID下位32bit候補・未検証）"
            return catalog.label(self.effect_id)
        except FileNotFoundError:
            return EFFECT_NAMES.get(self.effect_id, f"未分類 0x{self.effect_id:08X}" if self.effect_id is not None else "攻撃（効果IDなし）")

    @property
    def flags(self):
        return parse_flags(self.flag_bytes)

    def as_meter_log(self, timestamp: float | None = None) -> str:
        f = self.flags
        # Keep the existing 23-column Korea-compatible stream format.
        # 0=time, 1=source, 2=target, 3=skill, 4=effect ID, 5=damage,
        # 6=crit, then the remaining original FLAG_BITS order.
        # The legacy HTML looks for English internal class prefixes.  Keep
        # those in its WebSocket format while showing the Japanese candidate.
        label = self.skill_name
        try:
            entry = get_catalog().get(self.effect_id)
            if entry and entry.is_player and entry.class_internal and entry.class_internal not in label:
                label = f"{entry.symbol} / {label}"
        except FileNotFoundError:
            pass
        columns = [
            str(round((timestamp if timestamp is not None else self.timestamp) * 1000)),
            f"{self.source:016x}", f"{self.target:016x}", label,
            f"0x{self.effect_id:08x}" if self.effect_id is not None else "",
            str(self.damage),
        ] + [str(f[key]) for _, key, _ in FLAG_BITS if key != "not_dot"]
        assert len(columns) == 23
        return "|".join(columns)

class DamageDecoder:
    def __init__(self):
        self.buf = bytearray()
        self.total = 0

    def reset(self):
        self.buf.clear()

    def feed(self, payload: bytes, timestamp: float) -> list[Event]:
        self.buf.extend(payload)
        events = []
        while True:
            i = self.buf.find(FRAME_HEADER)
            if i == -1:
                self.buf = self.buf[-(len(FRAME_HEADER)-1):]
                break
            if i:
                del self.buf[:i]
            size = len(FRAME_HEADER) + PAYLOAD_LEN
            if len(self.buf) < size + 9:
                # Need the next message header to determine if 0x4FF7 follows.
                break
            frame = self.buf[len(FRAME_HEADER):size]
            source, target, damage = struct.unpack_from("<QQI", frame)
            effect_id = None
            effect_linkage = "missing"
            take = size
            # Most hits: 0x5243 -> 0x4FF7.
            # Break-extend capture: 0x5243 -> 0x5241 -> 0x4FF7.
            # Only traverse the exact, framed auxiliary record and verify its
            # source+target.  Do not blindly associate nearby unrelated effects.
            if self.buf[take:take+9] == AUX_HEADER:
                auxiliary_end = take + len(AUX_HEADER) + 29
                if len(self.buf) < auxiliary_end + 9:
                    break  # Wait for the whole auxiliary record and next header.
                aux_source, aux_target = struct.unpack_from("<QQ", self.buf, take+9)
                if (aux_source, aux_target) == (source, target):
                    take = auxiliary_end
                    effect_linkage = "via_0x5241"
            if self.buf[take:take+9] == EFFECT_HEADER:
                effect_end = take + len(EFFECT_HEADER) + 35
                if len(self.buf) < effect_end:
                    break  # 0x4FF7 may span two TCP segments.
                related = self.buf[take+9:effect_end]
                who, whom, code = struct.unpack_from("<QQQ", related)
                if (source, target) == (who, whom):
                    effect_id = code
                    effect_linkage = ("via_0x5241" if effect_linkage == "via_0x5241" else "direct")
                    take = effect_end
            if source and target and 0 < damage < 1_000_000_000:
                events.append(Event(timestamp, source, target, damage, effect_id, bytes(frame[32:38]), effect_linkage))
                self.total += 1
            del self.buf[:take]
        return events


class Flow:
    def __init__(self, decoder=None):
        self.next_seq = None
        self.pending: dict[int, tuple[bytes, float]] = {}
        self.decoder = decoder if decoder is not None else DamageDecoder()
        self.gap_since = None

    def feed(self, seq: int, data: bytes, timestamp: float) -> list[Event]:
        if not data:
            return []
        if self.next_seq is None:
            self.next_seq = seq
        if seq < self.next_seq:
            skip = self.next_seq - seq
            if skip >= len(data):
                return []  # TCP retransmission / overlap
            seq += skip
            data = data[skip:]
        if seq > self.next_seq:
            old = self.pending.get(seq)
            if old is None or len(data) > len(old[0]):
                self.pending[seq] = (data, timestamp)
            if self.gap_since is None:
                self.gap_since = time.monotonic()
            if sum(len(v[0]) for v in self.pending.values()) > 2_000_000 or (time.monotonic() - self.gap_since) > 3:
                # Missing packet: start fresh at earliest pending byte rather than merge corrupt data.
                LOGGER.warning("TCP gap detected; resynchronizing parser (some hits may be missed)")
                self.next_seq = min(self.pending)
                self.decoder.reset()
            else:
                return []
        results = []
        while True:
            if data and seq == self.next_seq:
                results += self.decoder.feed(data, timestamp)
                self.next_seq += len(data)
            matches = [(key, val) for key, val in self.pending.items() if key <= self.next_seq]
            if not matches:
                break
            k, (pending_bytes, pending_timestamp) = min(matches, key=lambda x: x[0])
            del self.pending[k]
            overlap = self.next_seq - k
            if overlap >= len(pending_bytes):
                data = b""
                continue
            seq = self.next_seq
            data = pending_bytes[overlap:]
            timestamp = pending_timestamp
        if not self.pending:
            self.gap_since = None
        return results


def pcapng_tcp(path: Path):
    """Yield (timestamp, src_ip, src_port, dst_ip, dst_port, tcp_seq, tcp_payload).

    Minimal EPB + Ethernet + IPv4/IPv6 reader sufficient for Wireshark PCAPNG.
    Deliberately avoids depending on globally-installed packet tools for offline checks.
    """
    binary = path.read_bytes()
    pos = 0
    endian = "<"
    interfaces = []
    while pos + 12 <= len(binary):
        block_type, size = struct.unpack_from(endian + "II", binary, pos)
        if block_type == 0x0A0D0D0A:
            marker = binary[pos + 8:pos + 12]
            if marker not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                raise ValueError("Invalid PCAPNG byte-order marker")
            endian = "<" if marker == b"\x4d\x3c\x2b\x1a" else ">"
            block_type, size = struct.unpack_from(endian + "II", binary, pos)
            interfaces = []
        if size < 12 or pos + size > len(binary):
            raise ValueError(f"Invalid PCAPNG block at byte {pos}")
        block = memoryview(binary)[pos + 8:pos + size - 4]
        if block_type == 1:
            linktype = struct.unpack_from(endian + "H", block, 0)[0]
            ts_scale = 1_000_000
            opt = 8
            while opt + 4 <= len(block):
                code, length = struct.unpack_from(endian + "HH", block, opt)
                if code == 0:
                    break
                if code == 9 and length >= 1:
                    v = block[opt + 4]
                    ts_scale = (2 ** (v & 127)) if v & 128 else (10 ** v)
                opt += 4 + ((length + 3) & ~3)
            interfaces.append((linktype, ts_scale))
        elif block_type == 6 and len(block) >= 20:
            iface, upper, lower, capture_len, orig_len = struct.unpack_from(endian + "IIIII", block, 0)
            if iface >= len(interfaces):
                pos += size
                continue
            linktype, ts_scale = interfaces[iface]
            timestamp = ((upper << 32) | lower) / ts_scale
            pkt = bytes(block[20:20 + capture_len])
            offset = 0
            if linktype == 1:  # Ethernet
                if len(pkt) < 14:
                    pos += size
                    continue
                ethertype = int.from_bytes(pkt[12:14], "big")
                offset = 14
                while ethertype in (0x8100, 0x88A8):
                    if len(pkt) < offset + 4:
                        break
                    ethertype = int.from_bytes(pkt[offset+2:offset+4], "big")
                    offset += 4
            elif linktype == 101:  # raw IPv4 / IPv6
                ethertype = 0x0800 if pkt and pkt[0] >> 4 == 4 else 0x86DD
            else:
                pos += size
                continue
            ip = pkt[offset:]
            if ethertype == 0x0800 and len(ip) >= 20:
                hdrlen = (ip[0] & 15) * 4
                if ip[9] != 6 or len(ip) < hdrlen + 20 or (int.from_bytes(ip[6:8], 'big') & 0x1FFF):
                    pos += size
                    continue
                src = str(ipaddress.IPv4Address(ip[12:16])); dst = str(ipaddress.IPv4Address(ip[16:20])); segment = ip[hdrlen:]
            elif ethertype == 0x86DD and len(ip) >= 60 and ip[6] == 6:
                src = str(ipaddress.IPv6Address(ip[8:24])); dst = str(ipaddress.IPv6Address(ip[24:40])); segment = ip[40:]
            else:
                pos += size
                continue
            sport, dport, seq = struct.unpack_from('!HHI', segment)
            tcp_hlen = (segment[12] >> 4) * 4
            if tcp_hlen >= 20 and len(segment) >= tcp_hlen:
                yield timestamp, src, sport, dst, dport, seq, segment[tcp_hlen:]
        pos += size


def collect(path: Path, port: int = 16000) -> tuple[list[Event], int]:
    flows: dict[tuple[str,int,str,int], list[tuple[int,bytes,float]]] = collections.defaultdict(list)
    for t, src, sport, dst, dport, seq, data in pcapng_tcp(path):
        if sport == port and data:
            flows[(src,sport,dst,dport)].append((seq,data,t))
    events = []
    for segments in flows.values():
        # Offline: reconstruct by sequence, de-duplicate retransmissions.
        stream = Flow()
        for seq, data, stamp in sorted(segments, key=lambda row:row[0]):
            events.extend(stream.feed(seq, data, stamp))
    return sorted(events, key=lambda e:e.timestamp), sum(len(v) for v in flows.values())


def save_csv(events: list[Event], path: Path):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        out = csv.writer(f)
        out.writerow(("JST", "attacker_id", "target_id", "damage", "effect_id", "skill_name", "flag_hex", "effect_linkage") + tuple(n for _,n,_ in FLAG_BITS))
        for e in events:
            t = dt.datetime.fromtimestamp(e.timestamp, JST).isoformat(timespec="milliseconds")
            out.writerow((t, f"0x{e.source:x}", f"0x{e.target:x}", e.damage,
                          f"0x{e.effect_id:08x}" if e.effect_id is not None else "",e.skill_name,
                          e.flag_bytes.hex(), e.effect_linkage) + tuple(e.flags[name] for _,name,_ in FLAG_BITS))


def show_report(events, packet_count):
    print(f"TCP 16000 server→PC packets with payload: {packet_count}")
    print(f"Candidate damage records (0x5243, payload 53B): {len(events)}")
    by_source=collections.defaultdict(lambda:[0,0])
    by_effect=collections.defaultdict(lambda:[0,0])
    for e in events:
        by_source[e.source][0]+=1
        by_source[e.source][1]+=e.damage
        by_effect[e.skill_name][0]+=1
        by_effect[e.skill_name][1]+=e.damage
    for uid, (hits, damage) in sorted(by_source.items(), key=lambda x:-x[1][1]):
        print(f"  attacker 0x{uid:x}: {hits} hits, {damage:,} total damage")
    print("Effect categories across all attackers (includes tentative categories):")
    for name,(hits,total) in sorted(by_effect.items(), key=lambda x:-x[1][1]):
        print(f"  {name}: {hits} hits, {total:,} damage")
    print("Caution: effect/flag mapping is provisional and based on one JP dummy capture.")


def listen_local(args, events=None):
    """Start WebSocket acceptor in a worker thread so Ctrl+C remains responsive.

    Accepted connections are explicitly closed during shutdown; this matters on
    Windows because `websockets.sync` uses non-daemon handler threads.
    """
    try:
        from websockets.sync.server import serve
    except ImportError:
        raise SystemExit("Install websockets in your venv: python -m pip install websockets")

    stop_event = threading.Event()
    connected = set()
    connected_lock = threading.Lock()
    outbox = queue.Queue(maxsize=2000)
    live_sniffer = None
    io_thread = None
    # Instrumentation is useful if the WebSocket connects but no damage appears.
    counters = {"packets": 0, "events": 0}
    flows = {}
    captured_lock = threading.Lock()

    def client_handler(ws):
        with connected_lock:
            connected.add(ws)
        try:
            for _ in ws:
                if stop_event.is_set():
                    break
        except Exception:
            LOGGER.debug("Browser WebSocket disconnected", exc_info=True)
        finally:
            with connected_lock:
                connected.discard(ws)

    def broadcast_log(line):
        with connected_lock:
            targets = list(connected)
        for ws in targets:
            try:
                ws.send(line)
            except Exception:
                with connected_lock:
                    connected.discard(ws)

    def send_events():
        while not stop_event.is_set():
            try:
                e = outbox.get(timeout=0.2)
            except queue.Empty:
                continue
            print(f"[hit] 0x{e.source:x} -> 0x{e.target:x}: {e.damage:,}  {e.skill_name}  crit={e.flags['crit']}", flush=True)
            broadcast_log(e.as_meter_log())

    def on_packet(pkt):
        try:
            from scapy.layers.inet import TCP
            from scapy.packet import Raw
            if TCP not in pkt or Raw not in pkt or int(pkt[TCP].sport) != args.port:
                return
            tcp = pkt[TCP]
            ip = tcp.underlayer
            key = (str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport))
            with captured_lock:
                counters["packets"] += 1
            if int(tcp.flags) & 0x05:  # TCP FIN/RST -- discard old stream
                flows.pop(key, None)
                return
            flow = flows.setdefault(key, Flow())
            decoded = flow.feed(int(tcp.seq), bytes(pkt[Raw].load), time.time())
            with captured_lock:
                counters["events"] += len(decoded)
            for event in decoded:
                try:
                    outbox.put_nowait(event)
                except queue.Full:
                    LOGGER.warning("Damage event queue is full; a hit was dropped")
        except Exception:
            LOGGER.exception("Error decoding captured packet")

    if events is None:
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            raise SystemExit("Install scapy and Npcap for passive live capture")
        capture_opts = dict(filter=f"tcp src port {args.port}", prn=on_packet, store=False)
        if args.iface:
            capture_opts["iface"] = args.iface
        live_sniffer = AsyncSniffer(**capture_opts)

    try:
        with serve(client_handler, "127.0.0.1", args.ws_port,
                   origins=["null"], close_timeout=1) as server:
            # On Windows, .serve_forever() may not handle Ctrl+C if it runs
            # directly in the main thread. Keep the main thread sleeping.
            acceptor = threading.Thread(target=server.serve_forever, daemon=True,
                                        name="local-websocket-acceptor")
            acceptor.start()
            print(f"Local WebSocket: ws://127.0.0.1:{args.ws_port}", flush=True)
            print("Open local_dps_jp/jp_meter.html in your browser.", flush=True)
            if events is not None:
                print(f"REPLAY mode: {len(events)} events, speed x{args.speed:g}", flush=True)
                previous = events[0].timestamp if events else 0
                # Replay on main thread; KeyboardInterrupt remains responsive.
                # Wait briefly for the browser to connect before sending events.
                while not stop_event.is_set():
                    with connected_lock:
                        has_browser = bool(connected)
                    if has_browser:
                        break
                    time.sleep(0.2)
                for e in events:
                    if stop_event.is_set():
                        break
                    wait = max(0.0, (e.timestamp - previous) / args.speed)
                    end = time.monotonic() + wait
                    while time.monotonic() < end and not stop_event.is_set():
                        time.sleep(max(0.0, min(0.2, end - time.monotonic())))
                    previous = e.timestamp
                    broadcast_log(e.as_meter_log(time.time()))
                print(f"Replay done ({len(events)} events). Ctrl+C to quit.", flush=True)
                while not stop_event.is_set():
                    time.sleep(0.2)
            else:
                print(f"LIVE mode: listening on tcp src port {args.port}"
                      + (f", interface={args.iface}" if args.iface else ", auto interface"), flush=True)
                live_sniffer.start()
                io_thread = threading.Thread(target=send_events, daemon=True,
                                             name="damage-event-sender")
                io_thread.start()
                previous = time.monotonic()
                while not stop_event.is_set():
                    time.sleep(0.2)
                    if time.monotonic() - previous >= 5:
                        with captured_lock:
                            count, hits = counters["packets"], counters["events"]
                        print(f"[capture] server->PC TCP packets: {count}, damage events: {hits}, flows: {len(flows)}", flush=True)
                        previous = time.monotonic()
    except KeyboardInterrupt:
        print("\nCtrl+C received, shutting down...", flush=True)
    finally:
        stop_event.set()
        # Closing the listening socket doesn't close accepted connections.
        # Close these so no WebSocket connection thread keeps Python running.
        with connected_lock:
            live_connections = list(connected)
        for ws in live_connections:
            try:
                ws.close(code=1001, reason="Local DPS stopped")
            except Exception:
                LOGGER.debug("WebSocket close error", exc_info=True)
        if live_sniffer is not None:
            try:
                if live_sniffer.running:
                    live_sniffer.stop(join=False)
                    live_sniffer.join(timeout=2)
            except Exception as exc:
                LOGGER.warning("Npcap stop warning: %s", exc)
        if io_thread:
            io_thread.join(timeout=1)
        print("DPS checker stopped.", flush=True)

def main():
    p=argparse.ArgumentParser(description="Japan Season 0 damage packet verification / passive DPS prototype")
    modes=p.add_mutually_exclusive_group(required=False)
    modes.add_argument("--pcap",type=Path,help="Offline analysis of Wireshark .pcapng")
    modes.add_argument("--replay",type=Path,help="Replay .pcapng damage events into local browser meter")
    modes.add_argument("--live",action="store_true",help="Passive live capture (requires Npcap / scapy)")
    p.add_argument("--list-ifaces",action="store_true",help="List Scapy/Npcap network interfaces")
    p.add_argument("--port",type=int,default=16000)
    p.add_argument("--ws-port",type=int,default=8000)
    p.add_argument("--iface",help="Optional network interface for Scapy")
    p.add_argument("--speed",type=float,default=3.0,help="Replay speed, default 3x")
    p.add_argument("--csv",type=Path,help="CSV output for offline analysis")
    args=p.parse_args()
    logging.basicConfig(level=logging.INFO,format="%(levelname)s: %(message)s")
    if args.list_ifaces:
        try:
            from scapy.all import show_interfaces
            show_interfaces()
        except ImportError:
            p.error("Install scapy to list capture interfaces")
        return
    if not (args.live or args.replay or args.pcap):
        p.error("Choose one of --pcap, --replay, --live or --list-ifaces")
    if args.speed<=0:p.error("--speed must be positive")
    if args.live:
        listen_local(args)
    else:
        records,n=collect(args.pcap or args.replay,args.port)
        show_report(records,n)
        if args.csv:
            save_csv(records,args.csv)
            print('CSV saved:',args.csv)
        if args.replay:
            listen_local(args,records)

if __name__=='__main__':main()
