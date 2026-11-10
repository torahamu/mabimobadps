"""Conservative labels for JP damage flags, without inventing a source skill.

Derived from Korean M-Inbody DamageFlags.kt bit positions, and tested with JP
practice captures (burn) and 2026-11-04 healer capture. 'dark' is the new bit.
The buff/status name is not encoded by this damage flag alone.
"""
from __future__ import annotations

# A bit indicating an element is not necessarily a named debuff or DoT.
ATTRIBUTES = (
    (3, 0x10, "出血"),
    (3, 0x20, "暗黒属性"),
    (3, 0x40, "火傷"),
    (3, 0x80, "聖属性"),
    (4, 0x01, "氷属性"),
    (4, 0x02, "雷属性"),
    (4, 0x04, "毒属性"),
    (4, 0x08, "精神属性"),
)

def flag_details(flag_bytes: bytes) -> dict[str, int]:
    b = bytes(flag_bytes).ljust(6, b"\0")
    return {
        "dark": int(bool(b[3] & 0x20)),
        "bleed": int(bool(b[3] & 0x10)),
        "holy": int(bool(b[3] & 0x80)),
        "electric": int(bool(b[4] & 0x02)),
        "mind": int(bool(b[4] & 0x08)),
        "dot_flag1": int(bool(b[1] & 0x08)),
        "dot_flag2": int(bool(b[1] & 0x80)),
        "dot_flag3": int(bool(b[2] & 0x01)),
        "dot_flag4": int(bool(b[4] & 0x10)),
        "is_dot": int(((b[1] & 0x88) == 0x88 and bool(b[2] & 0x01)) or bool(b[4] & 0x10)),
    }

def element_names(flag_bytes: bytes) -> list[str]:
    b = bytes(flag_bytes).ljust(6, b"\0")
    return [name for offset, mask, name in ATTRIBUTES if b[offset] & mask]

def attribute_label(flag_bytes: bytes) -> str:
    attrs = element_names(flag_bytes)
    return "・".join(attrs) if attrs else "属性未特定"

def unassigned_label(effect_id: int | None, flag_bytes: bytes) -> str | None:
    """Only fill in effect=0 / missing. Never infer which rune/skill applied it."""
    if effect_id not in (None, 0):
        return None
    details = flag_details(flag_bytes)
    attrs = element_names(flag_bytes)
    if details["is_dot"]:
        # Preserve v5.1's proven label for the Japanese burn capture.
        if attrs == ["火傷"]:
            return "火傷DoT（発生源未特定）"
        return f"{'・'.join(attrs) if attrs else '属性未特定'}DoT（発生源未特定）"
    if effect_id == 0 and attrs:
        return f"{'・'.join(attrs)}攻撃（効果IDゼロ・発生源未特定）"
    return None

def evidence(flag_bytes: bytes) -> str:
    if flag_details(flag_bytes)["is_dot"]:
        return f"ダメージフラグによるDoT・{attribute_label(flag_bytes)}判定（原因スキル/状態名未特定）"
    return f"ダメージ属性フラグ：{attribute_label(flag_bytes)}（原因スキル/状態名未特定）"
