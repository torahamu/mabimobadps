"""Offline Japanese skill-name catalog for Mabinogi Mobile packet effect IDs.

All three user-provided CSV files are included locally.  The catalog deliberately
preserves 'candidate' / 'estimated' evidence; a Japanese label is not proof that
its numeric ID is an official skill ID in the current game version.
"""
from __future__ import annotations
import csv
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_FILES = (
    ("総合辞書", "mabi_skill_id_dictionary_jp_candidates_20261103.csv"),
    ("プレイヤー候補", "mabi_player_skill_candidates_20261103.csv"),
    ("基本スキル", "mabi_player_skill_base_20261103.csv"),
)

# For one packet effect not currently in the supplied skill-ID CSVs.
# This is from the October 30 dummy-target test, NOT an official name mapping.
MANUAL_OBSERVED = {0x772815F3: ("通常攻撃", "通常攻撃", "氷結術師", "実戦照合・辞書未収録")}

@dataclass(frozen=True)
class SkillEntry:
    numeric_id: int
    symbol: str
    class_jp: str
    class_internal: str
    base: str
    action: str
    explanation: str
    evidence: str
    availability: str
    origin: str
    notes: str
    is_player: bool

    @property
    def display(self) -> str:
        # 2026-11-03 PCAP + user's screenshot: this specific numeric ID is
        # IceMage_BreakExtend, the Icicle Shackle break-extend hit.
        # Keep base_skill_jp_candidate intact for grouping into the base skill.
        if self.numeric_id == 0x46DDC8DC and self.symbol == "IceMage_BreakExtend":
            return "アイシクルシャックル（ブレイクエクステンド）"
        return self.action or self.base or self.symbol or f"未分類 0x{self.numeric_id:08X}"

    @property
    def evidence_short(self) -> str:
        if "パケット＋ユーザー実戦確認" in self.evidence: return "実戦照合"
        if "日本語スキル名との意味的一致" in self.evidence: return "名称推定"
        if "内部英語名からの仮訳" in self.evidence: return "仮訳"
        if "High系別ID" in self.evidence: return "High系名一致・推定"
        if "実戦照合" in self.evidence: return "実戦照合"
        if "未対応" in self.evidence or "対象外" in self.evidence: return "未検証"
        return "未検証"


class SkillCatalog:
    def __init__(self, data_dir: Path = DATA_DIR):
        self.by_id: dict[int, SkillEntry] = {}
        self.source_counts: dict[str, int] = {}
        self.data_dir = Path(data_dir)
        # The big dictionary supplies all symbols; the two curated lists take
        # precedence for overlapping IDs.  The candidate list adds verified variants.
        for origin, filename in DATA_FILES:
            path = self.data_dir / filename
            if not path.is_file():
                raise FileNotFoundError(f"スキル辞書が見つかりません: {path}")
            count = 0
            with path.open(encoding="utf-8-sig", newline="") as f:
                for row in csv.DictReader(f):
                    count += 1
                    try: ident = int(row["numeric_id_hex"], 16)
                    except (ValueError, KeyError, TypeError): continue
                    player = row.get("player_class_candidate", "").lower() == "true"
                    record = SkillEntry(
                        numeric_id=ident,
                        symbol=row.get("client_symbol_name", ""),
                        class_jp=row.get("class_jp", ""),
                        class_internal=row.get("class_internal", ""),
                        base=row.get("base_skill_jp_candidate", ""),
                        action=row.get("action_jp_candidate", ""),
                        explanation=row.get("internal_variant_explanation", ""),
                        evidence=row.get("evidence_level", ""),
                        availability=row.get("availability_note", ""),
                        origin=origin,
                        notes=row.get("notes", ""),
                        is_player=player,
                    )
                    # If a curated row has no Japanese name but the main dictionary
                    # had one, keep the informative one.  Never invent a translation.
                    old = self.by_id.get(ident)
                    if old is not None and old.display != old.symbol and record.display == record.symbol:
                        continue
                    self.by_id[ident] = record
            self.source_counts[origin] = count
        for ident, (base, action, class_jp, evidence) in MANUAL_OBSERVED.items():
            if ident not in self.by_id:
                self.by_id[ident] = SkillEntry(
                    ident, "IceMage_DefaultAttack / 手動照合", class_jp, "IceMage",
                    base, action, "", evidence, "日本S0", "実測補足", "2026-10-30 カカシ実測", True
                )

        # The comprehensive dictionary marks some High* copies as non-player,
        # while curated lists contain identical action suffixes as player skills.
        # These are DIFFERENT numeric IDs.  A match only suggests a JP label;
        # it never changes the source row or equates their numeric IDs.
        self.high_aliases: dict[int, SkillEntry] = {}
        self.high_alias_references: dict[int, SkillEntry] = {}
        player_symbols = {e.symbol: e for e in self.by_id.values() if e.is_player and e.symbol}
        for ident, original in self.by_id.items():
            if original.is_player or not original.symbol.startswith("High"):
                continue
            prefix, separator, suffix = original.symbol.partition("_")
            if not separator or prefix not in {"HighHealer", "HighArcher", "HighBard", "HighMage", "HighThief"}:
                # HighPriest_Abyss_* are enemy/boss-style names, not ordinary
                # Priest player skills; do not blindly strip every High prefix.
                continue
            root = prefix[len("High"):]
            # Exact remainder only: do NOT collapse _Explosion, _Panic, etc.
            candidates = [player_symbols.get(f"{p}_{suffix}") for p in (root, f"Expert{root}")]
            candidates = [e for e in candidates if e and (e.action or e.base)]
            if not candidates:
                continue
            names = {(e.action or e.base) for e in candidates}
            if len(names) != 1:
                # Ambiguous sibling actions: don't choose a label arbitrarily.
                continue
            ref = candidates[0]
            self.high_alias_references[ident] = ref
            self.high_aliases[ident] = replace(
                original,
                class_jp=ref.class_jp,
                base=ref.base,
                action=ref.action,
                evidence=(f"High系別ID・内部名の完全一致による日本語名候補（未検証）："
                          f"{original.symbol} ↔ {ref.symbol}; "
                          f"{ident:#010x} != {ref.numeric_id:#010x}"),
                origin=f"{original.origin} / 別IDの名称参照: {ref.origin}",
                notes=(f"{original.notes} / 別ID（{ref.numeric_id:#010x}）の日本語候補を名称参照。"
                       "同じ効果ID・同じ攻撃の証明ではありません。"),
                is_player=False,  # maintain the source classification
            )

    def high_alias_for(self, effect_id: int | None) -> SkillEntry | None:
        return self.high_aliases.get(effect_id) if effect_id is not None else None

    def high_alias_reference(self, effect_id: int | None) -> SkillEntry | None:
        return self.high_alias_references.get(effect_id) if effect_id is not None else None

    def display_entry(self, effect_id: int | None) -> SkillEntry | None:
        """Display-only alias, otherwise the original CSV entry."""
        return self.high_alias_for(effect_id) or self.get(effect_id)

    def get(self, effect_id: int | None) -> SkillEntry | None:
        return self.by_id.get(effect_id) if effect_id is not None else None

    def label(self, effect_id: int | None) -> str:
        if effect_id is None: return "攻撃（効果IDなし）"
        found = self.get(effect_id)
        if found and found.is_player: return found.display
        alias = self.high_alias_for(effect_id)
        if alias: return f"{alias.display}（High系別ID・名称候補）"
        return f"未分類 0x{effect_id:08X}"

    def rows(self, keyword: str = "", player_only: bool = False, limit: int = 300):
        words = keyword.casefold().split()
        result = []
        for original in self.by_id.values():
            row = self.high_alias_for(original.numeric_id) or original
            if player_only and not (row.is_player or self.high_alias_for(row.numeric_id)): continue
            if words:
                text = " ".join((row.display, row.symbol, row.class_jp, f"0x{row.numeric_id:08X}")).casefold()
                if not all(w in text for w in words): continue
            result.append(row)
        result.sort(key=lambda r:(not r.is_player, r.class_jp, r.display, r.numeric_id))
        return result[:limit], len(result)

@lru_cache(maxsize=1)
def get_catalog() -> SkillCatalog:
    return SkillCatalog()
