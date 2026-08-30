#!/usr/bin/env python3
"""Generate src/angle_attrs_table.rs from the E3D 3.1 exported catalog.

Angle attributes are the ones whose catalog `UNIT` field is `db1_hash("ANGL")`
(== 773119). Such an attribute, when it is stored in a single record word,
holds hundredths of a degree (centidegrees): the record word 4294958296
(-9000 as i32) is the -90.0 degrees `q att` prints. e3d-io's descriptor
decoder consults this table to surface those word-stored angles as a scaled
`Real` instead of an unsigned `Word`.

Source of truth: vendor/e3d-io/catalog/e3d31/noun_attr_fields.json (the live
AMS export, 2026-08-26). Run from the e3d-attlib crate root:

    python tools/gen_angle_attrs.py
"""
import json
import os
import sys

UNIT_ANGLE = 773119  # db1_hash("ANGL")

HERE = os.path.dirname(os.path.abspath(__file__))
FIELDS = os.path.normpath(
    os.path.join(HERE, "..", "..", "e3d-io", "catalog", "e3d31", "noun_attr_fields.json")
)
OUT = os.path.normpath(os.path.join(HERE, "..", "src", "angle_attrs_table.rs"))


def main() -> int:
    with open(FIELDS, "r", encoding="utf-8") as fh:
        records = json.load(fh)

    hashes = []
    for hash_str, record in records.items():
        fields = record.get("f", {})
        unit = fields.get("UNIT", {})
        if unit.get("i") == UNIT_ANGLE:
            hashes.append((int(hash_str), record.get("name", "?")))

    hashes.sort(key=lambda pair: pair[0])
    seen = set()
    uniq = []
    for h, name in hashes:
        if h in seen:
            continue
        seen.add(h)
        uniq.append((h, name))

    bang = 679457
    print(f"source: {FIELDS}")
    print(f"total attributes: {len(records)}")
    print(f"angle attributes (UNIT==ANGL): {len(uniq)}")
    print(f"BANG (679457) present: {bang in seen}")
    if uniq:
        print(f"hash range: {uniq[0][0]} .. {uniq[-1][0]}")
    print("sample:", ", ".join(f"{name}({h})" for h, name in uniq[:8]))

    lines = []
    lines.append(
        "// AUTO-GENERATED from ../e3d-io/catalog/e3d31/noun_attr_fields.json "
        "— DO NOT EDIT BY HAND"
    )
    lines.append(
        f"// {len(uniq)} attributes whose catalog UNIT is db1_hash(\"ANGL\") == "
        f"{UNIT_ANGLE} (E3D 3.1)."
    )
    lines.append("// Regenerate with tools/gen_angle_attrs.py. Sorted by hash for binary search.")
    lines.append("")
    lines.append("pub static ANGLE_ATTR_HASHES: &[u32] = &[")
    for h, name in uniq:
        lines.append(f"    0x{h:08X}, // {name}")
    lines.append("];")
    lines.append("")

    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print(f"wrote {OUT} ({len(uniq)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
