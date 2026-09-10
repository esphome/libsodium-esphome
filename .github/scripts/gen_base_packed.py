"""Generate the packed Ed25519 base point table walked by patch 10 and port/x25519_m15.c.

Reads the reference fe_25_5 table (32 tables x 8 points, each point three
field elements of ten limbs) and writes every second table as 32 byte
canonical field element encodings, expressed as little endian 32 bit words
so the table can live in flash on cores that need word reads.

Usage: gen_base_packed.py <fe_25_5/base.h> <base_packed.h>
"""

import re
import sys

P = 2**255 - 19
LIMB_OFFSETS = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230]
TABLES, POINTS, ELEMENTS, LIMBS = 32, 8, 3, 10
KEEP_EVERY = 2  # 16 of the 32 tables


def pack(limbs: list[int]) -> list[int]:
    value = sum(limb << offset for limb, offset in zip(limbs, LIMB_OFFSETS)) % P
    raw = value.to_bytes(32, "little")
    return [int.from_bytes(raw[i : i + 4], "little") for i in range(0, 32, 4)]


def main() -> None:
    src = re.sub(r"/\*.*?\*/", "", open(sys.argv[1]).read(), flags=re.S)
    nums = [int(x) for x in re.findall(r"-?\d+", src)]
    if len(nums) != TABLES * POINTS * ELEMENTS * LIMBS:
        sys.exit(f"unexpected limb count {len(nums)}")
    out = []
    for table in range(0, TABLES, KEEP_EVERY):
        rows = []
        for point in range(POINTS):
            words = []
            for element in range(ELEMENTS):
                base = ((table * POINTS + point) * ELEMENTS + element) * LIMBS
                words += pack(nums[base : base + LIMBS])
            rows.append("    { " + ", ".join(f"0x{w:08x}" for w in words) + " }")
        out.append("  {\n" + ",\n".join(rows) + "\n  }")
    with open(sys.argv[2], "w") as f:
        f.write(",\n".join(out) + "\n")


if __name__ == "__main__":
    main()
