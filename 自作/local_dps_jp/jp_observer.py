"""Japanese packet event observer (independent reimplementation of the approach in M-Inbody).

Only passively reads records. Action and FX layouts are from user's JP captures.
The M-Inbody buff record types are NOT demonstrated on Japan captures; they are
tracked in an isolated optional experimental decoder, with explicit provenance.
No external services, scripts, packet edits, or client modification.
"""
from __future__ import annotations

import collections
from dataclasses import dataclass, field
import struct
from pathlib import Path

from .jp_dps import Flow, pcapng_tcp

# These differ from the Korean M-Inbody protocol codes.
JP_ACTION = 0x1D4F8
JP_FX_NAME = 0x50D8
JP_PROFILE = 0x1D737
KOREAN_BUFF_START = 100048
KOREAN_BUFF_UPDATE = 100051
KOREAN_BUFF_END = 100049
KOREAN_BUFF_TYPES = {KOREAN_BUFF_START, KOREAN_BUFF_UPDATE, KOREAN_BUFF_END}

CLASS_PREFIX = {
    "IceMage": "氷結術師", "FireMage": "火炎術師", "LightningMage": "雷術師",
    "HighMage": "魔法使い", "HighThief": "盗賊系", "ExpertWarrior": "戦士系",
    "GreatSword": "大剣戦士", "SwordMaster": "剣術士", "DualBlades": "デュアルブレイド",
    "Bard": "吟遊詩人", "Healer": "ヒーラー", "Monk": "修道士",
    "Priest": "司祭", "HighArcher": "弓使い", "Arbalist": "クロスボウ",
    "Longbowman": "ロングボウ", "Novice": "戦士系",
}

@dataclass(frozen=True)
class Record:
    timestamp: float
    type: int
    codec: int
    payload: bytes


class RecordDecoder:
    """Incremental 9-byte-header protocol frame scanner, not game packet injector."""
    def __init__(self):
        self.buf = bytearray()
        self.synced = False

    def reset(self):
        self.buf.clear()
        self.synced = False

    def feed(self, data: bytes, timestamp: float) -> list[Record]:
        self.buf.extend(data)
        result = []
        while len(self.buf) >= 9:
            ty, size, codec = struct.unpack_from("<IIB", self.buf)
            # Broad but bounded check: initial capture may begin mid-record.
            plausible = size <= 2_000_000 and codec <= 1 and (self.synced or 0x4000 <= ty <= 0x30000)
            if not plausible:
                del self.buf[0]
                continue
            end = 9 + size
            if len(self.buf) < end:
                break
            self.synced = True
            result.append(Record(timestamp, ty, codec, bytes(self.buf[9:end])))
            del self.buf[:end]
        return result


@dataclass(frozen=True)
class Observation:
    timestamp: float
    kind: str
    type: int
    actor: int = 0
    target: int = 0
    name: str = ""
    effect_id: int | None = None
    detail: str = ""
    buff_instance: str = ""
    buff_id: int = 0
    stack: int = 0


def _read_utf16(payload: bytes, start: int, length: int) -> str | None:
    if not 2 <= length <= 512 or length & 1 or start + length > len(payload):
        return None
    try:
        value = payload[start:start+length].decode("utf-16-le").rstrip("\x00")
    except UnicodeError:
        return None
    if not value or any(ord(c) < 32 for c in value):
        return None
    return value


def parse_observation(record: Record) -> Observation | None:
    p, ty = record.payload, record.type
    if ty == JP_ACTION and record.codec == 0 and len(p) >= 20:
        actor = struct.unpack_from("<Q", p, 0)[0]
        length = struct.unpack_from("<I", p, 8)[0]
        name = _read_utf16(p, 12, length)
        if name is not None and len(p) >= 12 + length + 4:
            # Japanese action message puts numeric effect ID in last four bytes.
            effect_id = struct.unpack_from("<I", p, len(p)-4)[0]
            return Observation(record.timestamp, "action", ty, actor=actor,
                               name=name, effect_id=effect_id,
                               detail="日本版アクション通知")
    if ty == JP_FX_NAME and record.codec == 0 and len(p) >= 32:
        actor, target = struct.unpack_from("<QQ", p, 0)
        length = struct.unpack_from("<I", p, 24)[0]
        name = _read_utf16(p, 28, length)
        if name is not None:
            return Observation(record.timestamp, "fx", ty, actor=actor,
                               target=target, name=name,
                               detail="日本版エフェクト通知（ダメージではない）")
    if ty == JP_PROFILE and len(p) >= 35:
        # This profile record is NOT a party-roster message. Never link its
        # 64-bit profile identifier to battle entity IDs automatically.
        length = struct.unpack_from("<I", p, 27)[0]
        name = _read_utf16(p, 31, length)
        if name and len(name) <= 40:
            return Observation(record.timestamp, "profile", ty, name=name,
                               detail="プロフィール表示名（PT所属未確認）")
    if ty in KOREAN_BUFF_TYPES and record.codec == 0:
        return _parse_korean_buff(record)
    return None


def _parse_korean_buff(rec: Record) -> Observation | None:
    """Reference layout ONLY; no verified Japanese buff records so far."""
    ty, p = rec.type, rec.payload
    if len(p) < 20:
        return None
    actor = struct.unpack_from("<I", p)[0]
    instance = p[8:16].hex()
    if ty == KOREAN_BUFF_END:
        return Observation(rec.timestamp, "buff_end", ty, actor=actor,
                           buff_instance=instance, detail="KR仕様／JP未検証")
    if len(p) < 36:
        return None
    buff_id = struct.unpack_from("<I", p, 16)[0]
    stack = struct.unpack_from("<I", p, 24)[0]
    extra = struct.unpack_from("<I", p, 28)[0]
    if extra > 128 or 32 + 4 * extra + 4 > len(p) or stack > 65535:
        return None
    target = struct.unpack_from("<I", p, 32 + 4*extra)[0]
    return Observation(rec.timestamp, "buff_start" if ty == KOREAN_BUFF_START else "buff_update",
                       ty, actor=actor, target=target, buff_instance=instance,
                       buff_id=buff_id, stack=stack, detail="KR仕様／JP未検証")


@dataclass
class BuffInstance:
    instance: str
    buff_id: int
    source: int
    target: int
    stack: int
    start: float
    updated: float


class BuffTracker:
    """M-Inbody-style stateful instance tracking; only verified events are factual."""
    def __init__(self):
        self.active: dict[str, BuffInstance] = {}
        self.completed: list[tuple[BuffInstance, float]] = []
        self.counters = collections.Counter()

    def ingest(self, event: Observation):
        if not event.kind.startswith("buff_"):
            return
        self.counters[event.kind] += 1
        key = event.buff_instance
        if event.kind == "buff_end":
            entry = self.active.pop(key, None)
            if entry:
                self.completed.append((entry, max(0, event.timestamp - entry.start)))
        elif event.kind == "buff_start":
            old = self.active.pop(key, None)
            if old:
                self.completed.append((old, max(0, event.timestamp-old.start)))
            self.active[key] = BuffInstance(key, event.buff_id, event.actor,
                                            event.target, event.stack,
                                            event.timestamp, event.timestamp)
        else:
            old = self.active.get(key)
            if old:
                old.stack = event.stack
                old.target = event.target
                old.updated = event.timestamp


class ObserverState:
    def __init__(self):
        self.record_types = collections.Counter()
        self.events: list[Observation] = []
        self.action_ids: dict[int, str] = {}
        self.job_by_actor: dict[int, str] = {}
        self.profiles = collections.Counter()
        self.buff_tracker = BuffTracker()

    def ingest(self, rec: Record):
        self.record_types[rec.type] += 1
        event = parse_observation(rec)
        if event is None:
            return
        if len(self.events) < 100_000:
            self.events.append(event)
        if event.kind == "action" and event.effect_id not in (0, None):
            # A positive direct association, unlike nearest-hit guessing.
            self.action_ids[event.effect_id] = event.name
        if event.kind in ("action", "fx") and event.actor:
            for prefix, jp in CLASS_PREFIX.items():
                if event.name.casefold().startswith(prefix.casefold()+"_"):
                    self.job_by_actor[event.actor] = jp
                    break
        if event.kind == "profile":
            self.profiles[event.name] += 1
        if event.kind.startswith("buff_"):
            self.buff_tracker.ingest(event)

    def clear(self):
        self.__init__()


def collect_observations(path: Path, port: int = 16000) -> tuple[list[Record], ObserverState]:
    """Offline records from full TCP streams, de-duplicating retransmissions."""
    streams = collections.defaultdict(list)
    for when, src, sport, dst, dport, seq, data in pcapng_tcp(Path(path)):
        if sport == port and data:
            streams[(src, sport, dst, dport)].append((seq, data, when))
    records = []
    for segments in streams.values():
        flow = Flow(decoder=RecordDecoder())
        for seq, data, when in sorted(segments, key=lambda s:s[0]):
            records.extend(flow.feed(seq, data, when))
    records.sort(key=lambda r:r.timestamp)
    state = ObserverState()
    for rec in records:
        state.ingest(rec)
    return records, state
