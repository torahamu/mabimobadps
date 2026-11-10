"""Mabinogi Mobile JP — Tkinter DPS dashboard v5.

A native Windows-friendly GUI with no browser and no additional GUI packages.
Passive live capture uses scapy + Npcap. Offline PCAPNG decoding uses jp_dps.py.
No game injection, no patching, no outbound connections.
"""
from __future__ import annotations
import collections
import csv
import datetime as dt
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from . import jp_dps
from .skill_catalog import get_catalog, SkillCatalog, SkillEntry
from . import jp_observer
from .damage_labels import unassigned_label, flag_details, attribute_label, evidence as flag_evidence

BG = "#0A1120"
PANEL = "#111C2C"
PANEL_ALT = "#172438"
INPUT = "#0C1728"
EDGE = "#29374A"
INK = "#EDF4FF"
SUBTLE = "#93A8C1"
ACCENT = "#6AB8FF"
GREEN = "#7AD6B0"
PURPLE = "#BCA9FF"
ORANGE = "#F5BD75"
RED = "#F17B88"
FONT = ("Yu Gothic UI", 10)
FONT_SMALL = ("Yu Gothic UI", 9)
FONT_BOLD = ("Yu Gothic UI", 10, "bold")
JST = dt.timezone(dt.timedelta(hours=9))


def fmt(value):
    return f"{value:,.0f}"


def stamp(seconds):
    return dt.datetime.fromtimestamp(seconds, JST).strftime("%H:%M:%S.%f")[:-3]


def percent(n, d):
    return f"{100.0*n/d:.1f}%" if d else "—"


def skill_identity(event: jp_dps.Event, catalog: SkillCatalog, by_base: bool):
    special = unassigned_label(event.effect_id, event.flag_bytes)
    if special:
        return special, flag_evidence(event.flag_bytes), ""
    entry = catalog.get(event.effect_id)
    if entry and entry.is_player:
        label = (entry.base or entry.display) if by_base else entry.display
        evidence = "実戦照合" if event.effect_id == 0x46DDC8DC else entry.evidence_short
        return label, evidence, entry.class_jp
    high_alias = catalog.high_alias_for(event.effect_id)
    if high_alias:
        label = (high_alias.base or high_alias.display) if by_base else high_alias.display
        return label, "High系別ID・内部名一致（日本語名候補・未検証）", f"{high_alias.class_jp}（推定）"
    # Show the known internal symbol even when the broad dictionary marks it
    # NPC/non-player. Do not silently convert it into an official JP name.
    if entry and entry.symbol:
        return event.skill_name, "辞書内英語名・プレイヤー分類未確認", ""
    if event.effect_id is not None and event.effect_id > 0xFFFFFFFF:
        low_id = event.effect_id & 0xFFFFFFFF
        low = catalog.get(low_id)
        low_alias = catalog.high_alias_for(low_id)
        if low_alias:
            return event.skill_name, "複合ID下位32bit一致＋High系名候補（未検証）", f"{low_alias.class_jp}（推定）"
        if low and low.symbol:
            return event.skill_name, "複合IDの下位32bit一致・未検証", ""
    return event.skill_name, "未確認", ""


@dataclass
class SkillTotals:
    damage: int = 0
    hits: int = 0
    crits: int = 0
    add_hits: int = 0
    known: int = 0
    effects: set[int] = field(default_factory=set)
    evidence: set[str] = field(default_factory=set)


@dataclass
class ActorTotals:
    damage: int = 0
    hits: int = 0
    crits: int = 0
    add_hits: int = 0
    first: float | None = None
    last: float | None = None
    # A deque of (capture timestamp, damage) for rolling DPS.
    recent: collections.deque = field(default_factory=collections.deque)
    class_votes: collections.Counter = field(default_factory=collections.Counter)
    skills: dict[str, SkillTotals] = field(default_factory=dict)

    def rolling(self, clock):
        # Old items are dropped only for the rolling 5s metric; total remains.
        while self.recent and self.recent[0][0] < clock-5:
            self.recent.popleft()
        return sum(d for _, d in self.recent) / 5

    def avg(self):
        if self.first is None or self.last is None: return 0
        return self.damage / max(1, self.last-self.first)


class Meter:
    def __init__(self, catalog: SkillCatalog, observer=None):
        self.catalog = catalog
        self.observer = observer
        self.reset()

    def reset(self):
        self.actors: dict[int, ActorTotals] = {}
        self.events: list[tuple[float, jp_dps.Event]] = []
        self.count = 0
        self.latest = 0.0
        self.offset = 0.0
        self.last_raw: float | None = None

    def append(self, event: jp_dps.Event, when: float | None = None):
        # A replay of older files can be appended to the existing session.
        # In that case, place it after the last event without resetting totals.
        t = event.timestamp if when is None else when
        if self.last_raw is not None and t+self.offset < self.latest - 3:
            self.offset = self.latest+0.005-t
        adjusted = t+self.offset
        self.last_raw = t
        self.latest = max(self.latest, adjusted)
        actor = self.actors.setdefault(event.source, ActorTotals())
        actor.damage += event.damage
        actor.hits += 1
        actor.crits += event.flags["crit"]
        actor.add_hits += event.flags["add_hit"]
        actor.first = adjusted if actor.first is None else min(actor.first, adjusted)
        actor.last = adjusted if actor.last is None else max(actor.last, adjusted)
        actor.recent.append((adjusted, event.damage))
        label, evidence, class_jp = skill_identity(event, self.catalog, by_base=False)
        # Dynamic action->numeric effect link from actual Japanese action packets,
        # only when there is no verified/candidate dictionary entry.
        if self.observer is not None:
            if event.effect_id is not None and self.catalog.get(event.effect_id) is None:
                action_name = self.observer.action_ids.get(event.effect_id)
                if action_name and event.effect_id != 0:
                    label = f"{action_name}（通信内名）"
                    evidence = "発動ログ"
            class_jp = class_jp or self.observer.job_by_actor.get(event.source, "")
        if class_jp: actor.class_votes[class_jp] += 1
        group = actor.skills.setdefault(label, SkillTotals())
        group.damage += event.damage
        group.hits += 1
        group.crits += event.flags["crit"]
        group.add_hits += event.flags["add_hit"]
        group.known += int(event.effect_id is not None)
        if event.effect_id is not None: group.effects.add(event.effect_id)
        group.evidence.add(evidence)
        self.events.append((adjusted, event))
        self.count += 1
        return adjusted

    def top_actor(self) -> int | None:
        if not self.actors: return None
        return max(self.actors, key=lambda key: self.actors[key].damage)


class LiveCapture:
    def __init__(self, callback, on_error, observation_callback=None):
        self.callback = callback
        self.on_error = on_error
        self.observation_callback = observation_callback
        self.sniffer = None
        self.flows = {}
        self.observation_flows = {}
        self.record_count = 0
        self.packets = 0
        self.hits = 0
        self.active = False

    def start(self, iface: str | None, port: int):
        # Import scapy only when LIVE is requested. Offline GUI needs no scapy.
        from scapy.all import AsyncSniffer
        from scapy.layers.inet import TCP
        from scapy.packet import Raw

        def capture_packet(pkt):
            try:
                if TCP not in pkt or Raw not in pkt or int(pkt[TCP].sport) != port:
                    return
                tcp = pkt[TCP]
                ip = tcp.underlayer
                key = (str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport))
                self.packets += 1
                if int(tcp.flags) & 0x05:
                    self.flows.pop(key, None)
                    self.observation_flows.pop(key, None)
                    return
                flow = self.flows.setdefault(key, jp_dps.Flow())
                packet_bytes = bytes(pkt[Raw].load)
                now = time.time()
                hits = flow.feed(int(tcp.seq), packet_bytes, now)
                record_flow = self.observation_flows.setdefault(
                    key, jp_dps.Flow(decoder=jp_observer.RecordDecoder()))
                records = record_flow.feed(int(tcp.seq), packet_bytes, now)
                if records:
                    self.record_count += len(records)
                    if self.observation_callback:
                        self.observation_callback(records)
                if hits:
                    self.hits += len(hits)
                    self.callback(hits)
            except Exception as err:
                self.on_error(str(err))

        args = {"filter": f"tcp src port {port}", "prn": capture_packet, "store": False}
        if iface: args["iface"] = iface
        self.sniffer = AsyncSniffer(**args)
        self.sniffer.start()
        self.active = True

    def stop(self):
        if not self.sniffer:
            self.active = False
            return
        try:
            if self.sniffer.running:
                self.sniffer.stop(join=False)
        except Exception:
            pass
        self.active = False
        self.sniffer = None
        self.flows.clear()
        self.observation_flows.clear()


class Dashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mabinogi Mobile JP | Damage Lab v5.4")
        self.configure(bg=BG)
        self.geometry("1320x850")
        self.minsize(1020, 680)
        self.catalog = get_catalog()
        self.observer = jp_observer.ObserverState()
        self.meter = Meter(self.catalog, self.observer)
        self.bus = queue.Queue(maxsize=10000)
        self.capture: LiveCapture | None = None
        self.run_token = 0
        self.mode = "idle"
        self.current_replay = []
        self.current_recordings = []
        self.replay_obs_index = 0
        self.replay_index = 0
        self.replay_anchor = 0.0
        self.replay_stamp = 0.0
        self.loaded_file = ""
        self.actor_aliases = {}
        self.current_actor: int | None = None
        self.latest_log_id = 0
        self.last_status = "待機中"
        self.last_error = ""
        self._dirty = True
        self._dict_job = None
        self._build_styles()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.after(100, self._process_queue)
        self.after(300, self._ticker)

    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=INK, font=FONT)
        style.configure("Sub.TLabel", background=BG, foreground=SUBTLE, font=FONT_SMALL)
        style.configure("Panel.TLabel", background=PANEL, foreground=INK, font=FONT)
        style.configure("PanelSub.TLabel", background=PANEL, foreground=SUBTLE, font=FONT_SMALL)
        style.configure("TButton", font=FONT_BOLD, background=PANEL_ALT, foreground=INK,
                        padding=(13, 8), borderwidth=0)
        style.map("TButton", background=[("active", "#234363"), ("disabled", "#162337")],
                  foreground=[("disabled", "#61768F")])
        style.configure("Accent.TButton", background="#2B75BD", foreground="#FFFFFF")
        style.map("Accent.TButton", background=[("active", "#409BE6")])
        style.configure("Danger.TButton", background="#402E3B", foreground="#FFBAC4")
        style.map("Danger.TButton", background=[("active", "#65404C")])
        style.configure("TCheckbutton", background=PANEL, foreground=INK, font=FONT_SMALL)
        style.map("TCheckbutton", background=[("active", PANEL)], foreground=[("disabled", SUBTLE)])
        style.configure("TEntry", fieldbackground=INPUT, foreground=INK, insertcolor=INK,
                        bordercolor=EDGE, lightcolor=EDGE, darkcolor=EDGE, padding=6)
        style.configure("TCombobox", fieldbackground=INPUT, background=INPUT, foreground=INK,
                        selectbackground=INPUT, selectforeground=INK, bordercolor=EDGE, padding=5)
        style.map("TCombobox", fieldbackground=[("readonly", INPUT)],
                  foreground=[("readonly", INK)], selectbackground=[("readonly", INPUT)])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=SUBTLE, padding=(19, 9), font=FONT_BOLD)
        style.map("TNotebook.Tab", background=[("selected", PANEL_ALT)], foreground=[("selected", INK)])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=INK,
                        rowheight=28, bordercolor=EDGE, font=FONT_SMALL)
        style.map("Treeview", background=[("selected", "#284A6A")], foreground=[("selected", "#FFFFFF")])
        style.configure("Treeview.Heading", background=PANEL_ALT, foreground=SUBTLE,
                        font=FONT_BOLD, padding=(9, 9), borderwidth=0)
        style.map("Treeview.Heading", background=[("active", "#284158")])
        style.configure("Vertical.TScrollbar", background=PANEL_ALT, troughcolor=BG)

    def _text(self, parent, content, size=10, weight="normal", fg=INK, bg=None, **kwargs):
        return tk.Label(parent, text=content, font=("Yu Gothic UI", size, weight),
                        fg=fg, bg=bg or parent.cget("bg"), anchor="w", **kwargs)

    def _panel(self, parent, **kwargs):
        return tk.Frame(parent, bg=PANEL, highlightbackground=EDGE, highlightthickness=1, **kwargs)

    def _build_ui(self):
        top = tk.Frame(self, bg=BG, padx=22, pady=13)
        top.pack(fill="x")
        left_title = tk.Frame(top, bg=BG)
        left_title.pack(side="left", fill="x", expand=True)
        self._text(left_title, "❄  MOBINOGI  /  DAMAGE LAB", 18, "bold").pack(anchor="w")
        self._text(left_title, "v5.4  ·  日本版プロトコル解析  ·  ローカル専用  ·  自動戦闘終了なし",
                   9, fg=SUBTLE).pack(anchor="w", pady=(2,0))
        self.status_var = tk.StringVar(value="●  待機中")
        self.status_label = tk.Label(top, textvariable=self.status_var, bg=PANEL,
                                     fg=SUBTLE, font=FONT_BOLD, padx=15, pady=10)
        self.status_label.pack(side="right")
        shell = tk.Frame(self, bg=BG, padx=18)
        shell.pack(fill="both", expand=True)
        self.sidebar = self._panel(shell, width=260)
        self.sidebar.pack(side="left", fill="y", padx=(0,14), pady=(0,12))
        self.sidebar.pack_propagate(False)
        self.content = tk.Frame(shell, bg=BG)
        self.content.pack(side="left", fill="both", expand=True)
        self._build_sidebar()
        self._build_main()
        foot = tk.Frame(self, bg=BG, padx=22, pady=8)
        foot.pack(fill="x")
        self.footer_var = tk.StringVar(value="CSV: 3/3 読込済み  |  推定名称は公式確定ではありません")
        self._text(foot, "", 9, fg=SUBTLE, textvariable=self.footer_var).pack(side="left", fill="x", expand=True)
        self._text(foot, "パケットの閲覧・計測のみ / 非公式", 9, fg=SUBTLE).pack(side="right")

    def _build_sidebar(self):
        body = self.sidebar
        def section(text):
            self._text(body,text,10,"bold",fg=ACCENT,bg=PANEL).pack(anchor="w", padx=16,pady=(18,9))
        section("キャプチャ")
        self._text(body,"ネットワークアダプター",9,fg=SUBTLE,bg=PANEL).pack(anchor="w", padx=16)
        self.iface_var = tk.StringVar(value="自動選択")
        self.iface_combo = ttk.Combobox(body, textvariable=self.iface_var, values=["自動選択"], state="readonly")
        self.iface_combo.pack(fill="x", padx=16, pady=(6,5))
        ttk.Button(body,text="NIC一覧を更新",command=self.load_ifaces).pack(fill="x",padx=16,pady=(0,12))
        self.live_button = ttk.Button(body,text="●  ライブ計測を開始", style="Accent.TButton", command=self.toggle_live)
        self.live_button.pack(fill="x",padx=16,pady=(0,10))
        self._text(body,"TCP 16000 / Scapy + Npcap",9,fg=SUBTLE,bg=PANEL).pack(anchor="w",padx=16)
        ttk.Separator(body).pack(fill="x",padx=16,pady=(19,2))
        section("PCAPNG 解析")
        self.file_var = tk.StringVar(value="ファイル未選択")
        self._text(body,"キャプチャファイル",9,fg=SUBTLE,bg=PANEL).pack(anchor="w",padx=16)
        self._text(body,"",9,fg=INK,bg=PANEL,textvariable=self.file_var,wraplength=218,justify="left").pack(anchor="w",padx=16,pady=(5,7))
        ttk.Button(body,text="PCAPNGを開く",command=self.pick_file).pack(fill="x",padx=16,pady=(0,9))
        self._text(body,"再生速度",9,fg=SUBTLE,bg=PANEL).pack(anchor="w",padx=16)
        self.speed_var = tk.StringVar(value="3x")
        ttk.Combobox(body,textvariable=self.speed_var,values=["1x","3x","10x","30x","即時"],state="readonly").pack(fill="x",padx=16,pady=(5,10))
        self.replay_btn = ttk.Button(body,text="▶  読み込んだデータを再生",command=self.start_replay)
        self.replay_btn.pack(fill="x",padx=16,pady=(0,8))
        self.stop_btn = ttk.Button(body,text="■  再生を停止",command=self.stop_replay)
        self.stop_btn.pack(fill="x",padx=16)
        ttk.Separator(body).pack(fill="x",padx=16,pady=(21,2))
        section("集計・操作")
        ttk.Button(body,text="↻  集計をリセット",style="Danger.TButton",command=self.reset_meter).pack(fill="x",padx=16,pady=(0,9))
        ttk.Button(body,text="↓  ダメージCSV保存",command=self.export_csv).pack(fill="x",padx=16,pady=(0,8))
        ttk.Button(body,text="↓  通信観測CSV保存",command=self.export_observations).pack(fill="x",padx=16)
        self.capture_note = tk.StringVar(value="受信パケット 0 / ヒット 0")
        self._text(body,"",9,fg=SUBTLE,bg=PANEL,wraplength=220,
                   textvariable=self.capture_note,justify="left").pack(anchor="w",padx=16,pady=(18,8))
        self._text(body,"※ PTメンバーの行動IDが見えても、\n他人の実ダメージが届くとは限りません。",
                   9,fg=SUBTLE,bg=PANEL,justify="left").pack(anchor="w",padx=16,pady=(10,0))

    def _tree(self, parent, columns, headings, widths, stretch=None):
        frame = tk.Frame(parent,bg=PANEL)
        tree = ttk.Treeview(frame,columns=columns,show="headings",selectmode="browse")
        for c,h,w in zip(columns,headings,widths):
            tree.heading(c,text=h)
            tree.column(c,width=w,minwidth=55,anchor="e" if c in ("damage","dps","rolling","hits","pct","crit","add") else "w",
                        stretch=(c in (stretch or [])))
        bar = ttk.Scrollbar(frame,orient="vertical",command=tree.yview)
        tree.configure(yscrollcommand=bar.set)
        tree.pack(side="left",fill="both",expand=True)
        bar.pack(side="right",fill="y")
        return frame,tree

    def _build_main(self):
        self.tabs=ttk.Notebook(self.content)
        self.tabs.pack(fill="both",expand=True,pady=(0,13))
        self.page_dash=tk.Frame(self.tabs,bg=BG)
        self.page_dict=tk.Frame(self.tabs,bg=BG)
        self.page_log=tk.Frame(self.tabs,bg=BG)
        self.page_observer=tk.Frame(self.tabs,bg=BG)
        self.tabs.add(self.page_dash,text="  ダッシュボード  ")
        self.tabs.add(self.page_dict,text="  スキル辞書  ")
        self.tabs.add(self.page_log,text="  ダメージ履歴  ")
        self.tabs.add(self.page_observer,text="  通信・バフ検証  ")
        self._build_dash()
        self._build_dictionary()
        self._build_log()
        self._build_observer()

    def _build_dash(self):
        frame=self.page_dash
        cards=tk.Frame(frame,bg=BG)
        cards.pack(fill="x",pady=(8,12))
        self.stat_labels={}
        for index,(key,title,fg) in enumerate([
            ("total","累計ダメージ",INK),
            ("avg","平均 DPS",ACCENT),
            ("rolling","直近5秒 DPS",GREEN),
            ("crit","クリティカル率",PURPLE),
        ]):
            card=self._panel(cards)
            card.grid(row=0,column=index,sticky="nsew",padx=(0,10 if index<3 else 0))
            cards.columnconfigure(index,weight=1,uniform="stats")
            self._text(card,title,10,fg=SUBTLE,bg=PANEL).pack(anchor="w",padx=15,pady=(14,5))
            v=self._text(card,"—",22,"bold",fg=fg,bg=PANEL)
            v.pack(anchor="w",padx=15,pady=(0,12))
            self.stat_labels[key]=v
        panel=self._panel(frame)
        panel.pack(fill="x",pady=(0,12))
        row=tk.Frame(panel,bg=PANEL)
        row.pack(fill="x",padx=15,pady=(13,11))
        self._text(row,"攻撃者ID",10,"bold",bg=PANEL).pack(side="left",padx=(0,13))
        self.actor_var=tk.StringVar(value="自動（累計ダメージ最大）")
        self.actor_combo=ttk.Combobox(row,textvariable=self.actor_var,state="readonly",width=30)
        self.actor_combo["values"]=["自動（累計ダメージ最大）"]
        self.actor_combo.pack(side="left")
        self.actor_combo.bind("<<ComboboxSelected>>",lambda _:self._mark_dirty())
        self._text(row,"表示名",9,fg=SUBTLE,bg=PANEL).pack(side="left",padx=(17,7))
        self.alias_var=tk.StringVar()
        self.alias_entry=ttk.Entry(row,textvariable=self.alias_var,width=14)
        self.alias_entry.pack(side="left")
        ttk.Button(row,text="名前を設定",command=self.set_alias).pack(side="left",padx=(8,0))
        self.interval_var=tk.StringVar(value="計測区間 00:00 / 手動リセット")
        self._text(row,"",9,fg=SUBTLE,bg=PANEL,textvariable=self.interval_var).pack(side="right",padx=(9,0))
        lower = tk.PanedWindow(frame,orient="vertical",bg=BG,sashwidth=6,showhandle=False,
                               bd=0,relief="flat",sashrelief="flat")
        lower.pack(fill="both",expand=True)
        upper=self._panel(lower)
        bottom=self._panel(lower)
        lower.add(upper,minsize=190,stretch="always")
        lower.add(bottom,minsize=240,stretch="always")
        head=tk.Frame(upper,bg=PANEL)
        head.pack(fill="x",padx=14,pady=(10,4))
        self._text(head,"攻撃者別",12,"bold",bg=PANEL).pack(side="left")
        self._text(head,"本人IDは自動候補。PTメンバーのDPSは未保証",9,fg=SUBTLE,bg=PANEL).pack(side="right")
        box,self.actors_tree=self._tree(upper,
            ("actor","class","damage","dps","rolling","hits"),
            ("攻撃者ID","職業候補","累計ダメージ","平均DPS","直近5秒","ヒット"),
            (170,130,155,110,110,85),stretch=["actor","class"])
        box.pack(fill="both",expand=True,padx=12,pady=(0,10))
        # Only user clicks should pin the selected actor. Programmatic table
        # highlighting must not disable automatic highest-damage selection.
        self.actors_tree.bind("<ButtonRelease-1>",self._select_actor_row)
        head=tk.Frame(bottom,bg=PANEL)
        head.pack(fill="x",padx=14,pady=(10,7))
        self._text(head,"スキル別ダメージ",12,"bold",bg=PANEL).pack(side="left")
        self.group_var=tk.BooleanVar(value=False)
        ttk.Checkbutton(head,text="基本スキルに集約",variable=self.group_var,command=self._mark_dirty).pack(side="right")
        split=tk.Frame(bottom,bg=PANEL)
        split.pack(fill="both",expand=True,padx=12,pady=(0,9))
        frame_table,self.skill_tree=self._tree(split,
            ("name","damage","pct","hits","crit","add","trust"),
            ("スキル / 攻撃名","ダメージ","割合","ヒット","クリ率","追加攻撃","根拠"),
            (280,120,80,75,75,80,85),stretch=["name"])
        frame_table.pack(side="left",fill="both",expand=True)
        chart_box=tk.Frame(split,bg=PANEL,width=222)
        chart_box.pack(side="left",fill="y",padx=(10,0))
        chart_box.pack_propagate(False)
        self._text(chart_box,"ダメージ内訳 TOP 6",10,"bold",bg=PANEL).pack(anchor="w",pady=(2,5))
        self.chart=tk.Canvas(chart_box,bg=PANEL,highlightthickness=0,height=185)
        self.chart.pack(fill="both",expand=True)

    def _build_dictionary(self):
        frame=self.page_dict
        panel=self._panel(frame)
        panel.pack(fill="both",expand=True,pady=(8,0))
        head=tk.Frame(panel,bg=PANEL)
        head.pack(fill="x",padx=14,pady=(15,10))
        self._text(head,"ID → 日本語スキル名",13,"bold",bg=PANEL).pack(side="left",padx=(0,18))
        self.query_var=tk.StringVar()
        search=ttk.Entry(head,textvariable=self.query_var,width=37)
        search.pack(side="left",fill="x",expand=True)
        search.insert(0,"")
        self.query_var.trace_add("write",lambda *_:self.schedule_dictionary_refresh())
        self.player_only=tk.BooleanVar(value=True)
        ttk.Checkbutton(head,text="プレイヤー職のみ",variable=self.player_only,
                        command=self.refresh_dictionary).pack(side="left",padx=(13,0))
        self.dict_count=tk.StringVar(value="")
        self._text(panel,"",9,fg=SUBTLE,bg=PANEL,textvariable=self.dict_count).pack(anchor="w",padx=15,pady=(0,8))
        box,self.dict_tree=self._tree(panel,
            ("id","jp","symbol","class","trust"),
            ("16進ID","日本語名候補","内部シンボル名","職業","根拠"),
            (135,270,335,155,100),stretch=["jp","symbol"])
        box.pack(fill="both",expand=True,padx=12,pady=(0,9))
        self.dict_tree.bind("<<TreeviewSelect>>",self.show_dictionary_detail)
        self.dict_detail=tk.StringVar(value="行を選ぶと、名称の根拠や実装状況が表示されます。")
        detail=self._panel(panel)
        self._text(panel,"",9,fg=SUBTLE,bg=PANEL,textvariable=self.dict_detail,
                   wraplength=860,justify="left").pack(fill="x",padx=15,pady=(0,14))
        self.refresh_dictionary()

    def _build_log(self):
        frame=self.page_log
        panel=self._panel(frame)
        panel.pack(fill="both",expand=True,pady=(8,0))
        self._text(panel,"受信ダメージ履歴（最新300件表示・CSV出力は全件）",12,"bold",bg=PANEL).pack(anchor="w",padx=14,pady=(13,12))
        box,self.log_tree=self._tree(panel,
            ("time","source","target","damage","name","flags","id"),
            ("時刻 JST","攻撃者","対象","ダメージ","日本語名（候補）","判定","効果ID"),
            (105,110,110,105,280,180,115),stretch=["name"])
        box.pack(fill="both",expand=True,padx=12,pady=(0,12))

    def _build_observer(self):
        frame = self.page_observer
        self.obs_info = tk.StringVar(value="日本版イベント観測待ち。バフ種別はまだ特定されていません。")
        self._text(frame, "通信から得た内部名・プロフィール候補・バフプロトコル調査", 12,
                   "bold", bg=BG).pack(anchor="w", pady=(12,7))
        self._text(frame, "", 9, fg=SUBTLE, bg=BG, textvariable=self.obs_info,
                   wraplength=940, justify="left").pack(fill="x", pady=(0,11))
        top = tk.PanedWindow(frame, orient="vertical", bg=BG, sashwidth=6,
                             bd=0, showhandle=False)
        top.pack(fill="both", expand=True)
        first = self._panel(top)
        second = self._panel(top)
        third = self._panel(top)
        top.add(first, minsize=145, stretch="always")
        top.add(second, minsize=140, stretch="always")
        top.add(third, minsize=135, stretch="always")
        self._text(first, "日本版のアクション／演出ログ（PTの実ダメージではありません）",
                   10,"bold",bg=PANEL).pack(anchor="w",padx=12,pady=(9,7))
        holder, self.obs_tree = self._tree(first,
            ("time","type","actor","name","effect"),
            ("時刻","種別","戦闘ID","内部名","関連ID"),
            (107,95,110,350,110), stretch=["name"])
        holder.pack(fill="both",expand=True,padx=10,pady=(0,8))
        self._text(second, "プロフィール名候補（PT名簿ではない）・観測職業",
                   10,"bold",bg=PANEL).pack(anchor="w",padx=12,pady=(9,7))
        holder, self.obs_actor_tree = self._tree(second,
            ("source","actor","info"), ("識別子・表示名","判定","根拠"),
            (240,175,390), stretch=["info"])
        holder.pack(fill="both",expand=True,padx=10,pady=(0,8))
        self._text(third, "バフ検証（韓国版の管理方式を参考／日本版通知コード未特定）",
                   10,"bold",bg=PANEL).pack(anchor="w",padx=12,pady=(9,7))
        parts=tk.Frame(third,bg=PANEL)
        parts.pack(fill="both",expand=True,padx=10,pady=(0,8))
        holder, self.obs_buff_tree = self._tree(parts,
            ("id","source","target","stack","elapsed"),
            ("Buff ID","付与元","対象","スタック","経過秒"),
            (125,110,110,70,90), stretch=["id"])
        holder.pack(side="left",fill="both",expand=True)
        side=tk.Frame(parts,bg=PANEL,width=205)
        side.pack(side="left",fill="y",padx=(10,0))
        side.pack_propagate(False)
        self._text(side,"観測したレコード型",9,"bold",bg=PANEL).pack(anchor="w",pady=(0,4))
        holder2, self.obs_type_tree = self._tree(side,
            ("type","count"),("種別","件数"),(110,85))
        holder2.pack(fill="both",expand=True)

    def _render_observer(self):
        state = self.observer
        n_actions = sum(x.kind == "action" for x in state.events)
        n_fx = sum(x.kind == "fx" for x in state.events)
        self.obs_info.set(
            f"解析レコード {sum(state.record_types.values()):,}件 / アクション {n_actions:,}件 / "
            f"FX {n_fx:,}件 / 動的ID対応 {len(state.action_ids)}種類。 "
            f"バフ付与・更新・解除 {sum(state.buff_tracker.counters.values())}件（JPでは未検証）。 "
            f"プロフィール名はPT所属や戦闘IDと直接対応しません。")
        t = self.obs_tree
        t.delete(*t.get_children())
        interesting = [x for x in state.events if x.kind in ("action", "fx")][-200:]
        for i, item in enumerate(reversed(interesting)):
            t.insert("", "end", iid=f"obs_{i}",
                     values=(stamp(item.timestamp), item.kind,
                             f"0x{item.actor:X}" if item.actor else "—",
                             item.name,
                             f"0x{item.effect_id:08X}" if item.effect_id is not None else "—"))
        a = self.obs_actor_tree
        a.delete(*a.get_children())
        for i, (uid, cls) in enumerate(sorted(state.job_by_actor.items())):
            a.insert("", "end", iid=f"job_{i}", values=(f"0x{uid:X}", cls, "日本版エフェクトの英語接頭辞から推定"))
        for i, (name, count) in enumerate(state.profiles.most_common(100)):
            a.insert("", "end", iid=f"profile_{i}", values=(name, "プロフィール候補", f"{count}件／PT名簿ではない"))
        b = self.obs_buff_tree
        b.delete(*b.get_children())
        for i, instance in enumerate(state.buff_tracker.active.values()):
            b.insert("", "end", iid=f"buff_{i}", values=(f"0x{instance.buff_id:08X}",
                       f"0x{instance.source:X}", f"0x{instance.target:X}",
                       instance.stack, f"{max(0,state.events[-1].timestamp-instance.start):.1f}" if state.events else "0"))
        types=self.obs_type_tree
        types.delete(*types.get_children())
        for i,(code,num) in enumerate(state.record_types.most_common(100)):
            types.insert("", "end", iid=f"type_{i}", values=(f"0x{code:X}", fmt(num)))

    def _set_status(self,text,color=SUBTLE):
        self.last_status=text
        self.status_var.set("●  "+text)
        self.status_label.configure(fg=color)

    def _mark_dirty(self):
        self._dirty=True

    def _send(self,kind,payload,token):
        try: self.bus.put_nowait((kind,payload,token))
        except queue.Full: self.last_error="GUIイベントキューが満杯になりました。"

    def load_ifaces(self):
        try:
            from scapy.all import get_if_list
            names=get_if_list()
            self.iface_combo["values"]=["自動選択"]+names
            self._set_status(f"NIC {len(names)} 件",GREEN)
        except Exception as exc:
            messagebox.showerror("NIC取得エラー",f"Scapy/Npcapが必要です。\n{exc}")

    def toggle_live(self):
        if self.mode=="live":
            self.stop_live()
            return
        if self.mode=="replay":self.stop_replay()
        self.run_token+=1
        token=self.run_token
        iface=self.iface_var.get()
        iface=None if iface=="自動選択" else iface
        self.capture=LiveCapture(lambda hits:self._send("events",hits,token),
                                 lambda error:self._send("error",error,token),
                                 lambda records:self._send("records",records,token))
        try:
            self.capture.start(iface,16000)
            self.mode="live"
            self.live_button.configure(text="■  ライブ計測を停止",style="Danger.TButton")
            self._set_status("ライブ計測中",GREEN)
        except Exception as exc:
            self.capture=None
            self.mode="idle"
            messagebox.showerror("ライブ起動失敗",
                f"ScapyとNpcap、NICの選択を確認してね。\n\n{exc}")

    def stop_live(self):
        if self.capture:self.capture.stop()
        self.run_token+=1
        self.mode="idle"
        self.live_button.configure(text="●  ライブ計測を開始",style="Accent.TButton")
        self._set_status("計測停止（データ保持）",SUBTLE)

    def pick_file(self):
        file=filedialog.askopenfilename(title="PCAPNGキャプチャファイルを選択",
                                        filetypes=[("Wireshark PCAPNG","*.pcapng"),("すべてのファイル","*.*")])
        if not file:return
        if self.mode=="replay": self.stop_replay()
        self.loaded_file=file
        self.file_var.set(Path(file).name)
        self._set_status("PCAPNG読み込み中",ORANGE)
        token=self.run_token
        def job():
            try:
                events,count=jp_dps.collect(Path(file))
                records, scan=jp_observer.collect_observations(Path(file))
                self._send("loaded",(file,events,count,records,scan),token)
            except Exception as exc:self._send("load_error",str(exc),token)
        threading.Thread(target=job,name="offline-pcap-loader",daemon=True).start()

    def start_replay(self):
        if not self.current_replay:
            messagebox.showinfo("再生待ち","先にPCAPNGファイルを選んで読み込んでね。")
            return
        if self.mode=="live":self.stop_live()
        if self.mode=="replay":self.stop_replay()
        self.mode="replay"
        self.run_token+=1
        self.replay_index=0
        self.replay_obs_index=0
        self.replay_anchor=time.monotonic()
        self.replay_stamp=self.current_replay[0].timestamp
        self._set_status(f"リプレイ中 0/{len(self.current_replay)}",ACCENT)
        self.after(30,self._replay_tick)

    def _replay_tick(self):
        if self.mode!="replay":return
        speed=self.speed_var.get()
        scale={"1x":1.0,"3x":3.0,"10x":10.0,"30x":30.0,"即時":float("inf")}.get(speed,3.0)
        virtual = (self.replay_stamp+(time.monotonic()-self.replay_anchor)*scale)
        records = self.current_replay
        # Replay protocol observations up to the same virtual capture time.
        o=0
        while self.replay_obs_index < len(self.current_recordings) and (scale == float("inf") or
                self.current_recordings[self.replay_obs_index].timestamp <= virtual) and o < 800:
            self.observer.ingest(self.current_recordings[self.replay_obs_index])
            self.replay_obs_index += 1
            o += 1
        n=0
        while self.replay_index<len(records) and (scale==float("inf") or records[self.replay_index].timestamp<=virtual) and n<400:
            event=records[self.replay_index]
            self.meter.append(event)
            self.replay_index+=1
            n+=1
        if n or o:self._dirty=True
        if self.replay_index>=len(records) and self.replay_obs_index>=len(self.current_recordings):
            self.mode="idle"
            self._set_status(f"再生完了 {len(records)} 件",GREEN)
            self._dirty=True
            return
        self._set_status(f"再生中 {self.replay_index}/{len(records)}",ACCENT)
        self.after(35 if n else 70,self._replay_tick)

    def stop_replay(self):
        if self.mode!="replay":return
        self.mode="idle"
        self.run_token+=1
        self._set_status("再生停止（データ保持）",SUBTLE)

    def reset_meter(self):
        # Always manual.  Live and replay remain active; new hits start a new session.
        self.meter.reset()
        self.observer.clear()
        self.current_actor=None
        self.actor_aliases.clear()
        self.actor_var.set("自動（累計ダメージ最大）")
        self.alias_var.set("")
        self._mark_dirty()
        self._set_status("集計リセット済み",GREEN)

    def export_csv(self):
        if not self.meter.events:
            messagebox.showinfo("CSV保存","まだダメージ記録がありません。")
            return
        output=filedialog.asksaveasfilename(title="解析結果CSVを保存",defaultextension=".csv",
                                           initialfile="mabinogi_jp_damage_v5.csv",
                                           filetypes=[("CSVファイル","*.csv")])
        if not output:return
        try:
            with open(output,"w",encoding="utf-8-sig",newline="") as f:
                writer=csv.writer(f)
                writer.writerow(["timestamp_jst","attacker_id","attacker_display","target_id","damage",
                                 "effect_id","skill_jp_candidate","base_skill_jp_candidate","internal_symbol",
                                 "evidence_level","class_jp","crit","add_hit","power","fast","dot","ice","invalid_damage_excluded",
                                 "fire","break","flag_hex","effect_linkage","flag_byte4_bit0x20_candidate",
                                 "dark","holy","electric","mind","bleed","dot_confirmed","damage_flag_classification","effect_id_low32_candidate",
                                 "high_name_reference_id","high_name_reference_symbol","high_name_matching_method"])
                for t,ev in self.meter.events:
                    entry=self.catalog.get(ev.effect_id)
                    alias=self.catalog.high_alias_for(ev.effect_id)
                    low_alias=(self.catalog.high_alias_for(ev.effect_id & 0xFFFFFFFF)
                               if ev.effect_id is not None and ev.effect_id > 0xFFFFFFFF else None)
                    low_id=ev.effect_id & 0xFFFFFFFF if low_alias else None
                    reference=self.catalog.high_alias_reference(low_id if low_alias else ev.effect_id)
                    effective=alias or low_alias or entry
                    label, observed_evidence, observed_class = skill_identity(ev, self.catalog, by_base=False)
                    evidence=("実戦照合：ブレイクエクステンドのダメージとIDを確認"
                              if ev.effect_id == 0x46DDC8DC else
                              observed_evidence if (ev.effect_id in (None,0) or not (entry and entry.is_player))
                              else entry.evidence)
                    writer.writerow([dt.datetime.fromtimestamp(t,JST).isoformat(timespec="milliseconds"),
                                     f"0x{ev.source:X}",self.actor_aliases.get(ev.source,""),
                                     f"0x{ev.target:X}",ev.damage,
                                     f"0x{ev.effect_id:08X}" if ev.effect_id is not None else "",
                                     label,effective.base if effective else "",
                                     entry.symbol if entry else low_alias.symbol if low_alias else "",evidence,
                                     entry.class_jp if entry and entry.is_player else observed_class,
                                     *[ev.flags[k] for k in ("crit","add_hit","power","fast","dot","ice")],
                                     "0xFFFFFFFF not counted",ev.flags["fire"],ev.flags["break"],
                                     ev.flag_bytes.hex(),ev.effect_linkage,int(bool(ev.flag_bytes[4] & 0x20)),
                                     *[flag_details(ev.flag_bytes)[name] for name in ("dark","holy","electric","mind","bleed","is_dot")],
                                     attribute_label(ev.flag_bytes),
                                     f"0x{ev.effect_id & 0xFFFFFFFF:08X}" if ev.effect_id is not None and ev.effect_id > 0xFFFFFFFF else "",
                                     f"0x{reference.numeric_id:08X}" if reference else "",
                                     reference.symbol if reference else "",
                                     ("複合64bitの下位32bit一致＋High系内部名完全一致（別ID・未検証）"
                                      if low_alias else "High接頭辞除去後の内部シンボル完全一致（別ID・未検証）") if reference else ""])
            self._set_status(f"CSV保存: {Path(output).name}",GREEN)
        except Exception as exc: messagebox.showerror("CSV出力失敗",str(exc))

    def export_observations(self):
        """Shareable metadata-only event CSV, not raw network payloads."""
        if not self.observer.events:
            messagebox.showinfo("観測CSV保存","まだ観測したアクション・プロフィール等がありません。")
            return
        output=filedialog.asksaveasfilename(title="通信観測CSVを保存",defaultextension=".csv",
            initialfile="mabinogi_jp_observations_v5_2.csv",filetypes=[("CSVファイル","*.csv")])
        if not output:return
        try:
            with open(output,"w",encoding="utf-8-sig",newline="") as f:
                writer=csv.writer(f)
                writer.writerow(["timestamp_jst","record_type","kind","entity_id",
                                 "related_id","internal_name_or_profile","effect_id",
                                 "note","buff_instance_id","buff_type_id","buff_stack"])
                for e in self.observer.events:
                    writer.writerow([dt.datetime.fromtimestamp(e.timestamp,JST).isoformat(timespec="milliseconds"),
                                     f"0x{e.type:X}",e.kind,
                                     f"0x{e.actor:X}" if e.actor else "",
                                     f"0x{e.target:X}" if e.target else "",e.name,
                                     f"0x{e.effect_id:08X}" if e.effect_id is not None else "",
                                     e.detail,e.buff_instance,f"0x{e.buff_id:X}" if e.buff_id else "",e.stack])
            self._set_status(f"観測CSV保存: {Path(output).name}",GREEN)
        except Exception as exc:messagebox.showerror("観測CSV出力失敗",str(exc))

    def set_alias(self):
        key=self._selected_id()
        if key is None:
            messagebox.showinfo("表示名","先にダメージを計測して、攻撃者IDを選んでね。")
            return
        self.actor_aliases[key]=self.alias_var.get().strip()[:36]
        self._dirty=True

    def _process_queue(self):
        n=0
        while n<250:
            try:kind,payload,token=self.bus.get_nowait()
            except queue.Empty:break
            n+=1
            if token!=self.run_token:continue
            if kind=="events":
                for hit in payload:self.meter.append(hit)
                self._dirty=True
            elif kind=="records":
                for item in payload:self.observer.ingest(item)
                self._dirty=True
            elif kind=="loaded":
                path, events, count, recordings, scan=payload
                if path==self.loaded_file:
                    self.current_replay=events
                    self.current_recordings=recordings
                    self._set_status(f"読み込み完了: {len(events)} ヒット",GREEN)
                    self.capture_note.set(f"オフライン: TCP {count:,} / 有効 {len(events):,} ヒット / レコード {len(recordings):,}")
            elif kind=="error":
                self.last_error=payload
                self._set_status("パケット処理エラー（履歴を確認）",RED)
            elif kind=="load_error":
                self._set_status("PCAP読み込み失敗",RED)
                messagebox.showerror("PCAPNG解析エラー",payload)
        self.after(100,self._process_queue)

    def _selected_id(self):
        s=self.actor_var.get()
        if s.startswith("0x"):
            try:
                token=s.split(" ")[0]
                val=int(token,16)
                if val in self.meter.actors:return val
            except ValueError:pass
        return self.meter.top_actor()

    def _select_actor_row(self,event=None):
        selected=self.actors_tree.selection()
        if not selected:return
        try: ident=int(selected[0],16)
        except ValueError:return
        self.actor_var.set(next((v for v in self.actor_combo["values"] if v.startswith(f"0x{ident:X} ")),f"0x{ident:X}"))
        self.alias_var.set(self.actor_aliases.get(ident,""))
        self._mark_dirty()

    def _ticker(self):
        if self.capture and self.mode=="live":
            self.capture_note.set(f"ライブ: TCP {self.capture.packets:,} / 有効 {self.capture.hits:,} ヒット / レコード {self.capture.record_count:,}")
            if self.capture.sniffer and not self.capture.sniffer.running:
                self._set_status("キャプチャ停止（NIC/Npcap確認）",RED)
        if self._dirty:self.render()
        elif self.mode=="live": self._update_rolling_only()
        self.after(400,self._ticker)

    def _update_rolling_only(self):
        selected=self._selected_id()
        actor=self.meter.actors.get(selected)
        self.stat_labels["rolling"].configure(text=fmt(actor.rolling(time.time())) if actor else "—")

    def render(self):
        self._dirty=False
        ordered=sorted(self.meter.actors.items(),key=lambda x:-x[1].damage)
        old=self.actor_var.get()
        labels=["自動（累計ダメージ最大）"]
        for key, a in ordered:
            name=self.actor_aliases.get(key,"")
            guessed=a.class_votes.most_common(1)[0][0] if a.class_votes else "不明"
            labels.append(f"0x{key:X}  {name or guessed}")
        self.actor_combo["values"]=labels
        if old not in labels:self.actor_var.set(labels[0])
        selected=self._selected_id()
        self.current_actor=selected
        actor=self.meter.actors.get(selected)
        if actor:
            clock=time.time() if self.mode=="live" else self.meter.latest
            self.stat_labels["total"].configure(text=fmt(actor.damage))
            self.stat_labels["avg"].configure(text=fmt(actor.avg()))
            self.stat_labels["rolling"].configure(text=fmt(actor.rolling(clock)))
            self.stat_labels["crit"].configure(text=percent(actor.crits,actor.hits))
            seconds=int(max(0,(actor.last or 0)-(actor.first or 0)))
            self.interval_var.set(f"計測区間 {seconds//3600:02d}:{seconds//60%60:02d}:{seconds%60:02d} / 手動リセット")
        else:
            for label in self.stat_labels.values():label.configure(text="—")
            self.interval_var.set("計測待機中 / 手動リセット")
        tree=self.actors_tree
        current_selection=tree.selection()
        tree.delete(*tree.get_children())
        for key,a in ordered:
            guess=a.class_votes.most_common(1)[0][0] if a.class_votes else "不明"
            display=self.actor_aliases.get(key,"")
            row=(f"0x{key:X}"+(f"  {display}" if display else ""),guess,fmt(a.damage),fmt(a.avg()),
                 fmt(a.rolling(time.time() if self.mode=="live" else self.meter.latest)),fmt(a.hits))
            tree.insert("", "end", iid=f"0x{key:X}",values=row)
        if selected is not None and tree.exists(f"0x{selected:X}"):
            tree.selection_set(f"0x{selected:X}")
        self._render_skills(actor)
        self._render_recent_logs()
        self._render_observer()
        self.footer_var.set(f"CSV: 3/3 読込済み  |  辞書 {len(self.catalog.by_id):,} ID  |  "
                            f"集計 {self.meter.count:,} ヒット / {len(self.meter.actors)} 攻撃者ID  |  推定名称は公式確定ではありません")

    def _render_skills(self,actor):
        tree=self.skill_tree
        tree.delete(*tree.get_children())
        if actor is None:
            self.draw_chart([])
            return
        by_base=self.group_var.get()
        totals={}
        for label,item in actor.skills.items():
            if not by_base:
                totals[label]=item
                continue
            first_entry=next((self.catalog.display_entry(i) for i in sorted(item.effects) if self.catalog.display_entry(i)),None)
            name=first_entry.base or label if first_entry else label
            existing=totals.setdefault(name,SkillTotals())
            existing.damage+=item.damage
            existing.hits+=item.hits
            existing.crits+=item.crits
            existing.add_hits+=item.add_hits
            existing.known+=item.known
            existing.effects.update(item.effects)
            existing.evidence.update(item.evidence)
        sorted_rows=sorted(totals.items(),key=lambda x:-x[1].damage)
        for i,(label,item) in enumerate(sorted_rows):
            trust=" / ".join(sorted(item.evidence))
            tree.insert("","end",iid=f"skill_{i}",values=(label,fmt(item.damage),percent(item.damage,actor.damage),
                         fmt(item.hits),percent(item.crits,item.hits),fmt(item.add_hits),trust))
        self.draw_chart(sorted_rows[:6])

    def draw_chart(self,items):
        canvas=self.chart
        canvas.delete("all")
        width=max(190,canvas.winfo_width())
        if not items:
            canvas.create_text(11,42,text="ヒット待機中",fill=SUBTLE,anchor="w",font=FONT_SMALL)
            return
        peak=max((s.damage for _,s in items),default=1)
        for i,(name,s) in enumerate(items):
            y=15+i*34
            text=name if len(name)<16 else name[:15]+"…"
            canvas.create_text(9,y,text=text,anchor="w",fill=SUBTLE,font=FONT_SMALL)
            canvas.create_rectangle(9,y+11,width-12,y+17,fill=PANEL_ALT,outline="")
            fill=max(1,(width-22)*s.damage/peak)
            canvas.create_rectangle(9,y+11,9+fill,y+17,fill=[ACCENT,GREEN,PURPLE,ORANGE,"#6F9BCE","#D09FCB"][i],outline="")

    def _render_recent_logs(self):
        tree=self.log_tree
        tree.delete(*tree.get_children())
        for i,(t,e) in enumerate(reversed(self.meter.events[-300:])):
            active=[(k,label) for k,label in (("crit","クリ"),("add_hit","追加"),("power","強打"),
                                             ("fast","連打"),("dot","DoT")) if e.flags[k]]
            if flag_details(e.flag_bytes)["dark"]: active.append(("dark", "暗黒"))
            labels=" ".join(label for _,label in active)
            tree.insert("","end",iid=f"event_{i}",values=(stamp(t),f"0x{e.source:X}",f"0x{e.target:X}",
                       fmt(e.damage),e.skill_name,labels,
                       f"0x{e.effect_id:08X}" if e.effect_id is not None else "—"))

    def schedule_dictionary_refresh(self):
        if self._dict_job is not None:self.after_cancel(self._dict_job)
        self._dict_job=self.after(250,self.refresh_dictionary)

    def refresh_dictionary(self):
        self._dict_job=None
        rows,count=self.catalog.rows(self.query_var.get(),self.player_only.get(),limit=350)
        tree=self.dict_tree
        tree.delete(*tree.get_children())
        for row in rows:
            tree.insert("","end",iid=f"id_{row.numeric_id:X}",
                        values=(f"0x{row.numeric_id:08X}",row.display,row.symbol,row.class_jp,row.evidence_short))
        self.dict_count.set(f"一致 {count:,} 件 / 表示 {len(rows):,} 件（最大350件）。数値ID・日本語名・英語内部名で検索できます。")

    def show_dictionary_detail(self,event=None):
        selected=self.dict_tree.selection()
        if not selected:return
        try:ident=int(selected[0][3:],16)
        except ValueError:return
        row=self.catalog.display_entry(ident)
        if row:
            self.dict_detail.set(f"{row.display}    |    {row.symbol}    |    {row.class_jp}    |    {row.availability}    |    "
                                 f"根拠: {row.evidence}    |    出典CSV: {row.origin}\n{row.notes}")

    def close(self):
        if self.capture:self.capture.stop()
        self.run_token+=1
        self.destroy()


def main():
    try:
        window=Dashboard()
    except Exception as exc:
        root=tk.Tk()
        root.withdraw()
        messagebox.showerror("起動エラー",f"GUIを起動できませんでした。\n\n{exc}")
        root.destroy()
        raise
    window.mainloop()


if __name__=="__main__":
    main()
