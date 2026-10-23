"""Minimal QR Code → SVG encoder (byte mode, ECC level M). No third-party deps.

Supports versions 1–10, enough for typical absolute verify URLs.
"""
# @lat: [[interfaces#Public report verification#QR]]

from __future__ import annotations

# Capacity (bytes) for ECC-M, byte mode (ISO/IEC 18004).
_CAPACITY_M = {
    1: 14,
    2: 26,
    3: 42,
    4: 62,
    5: 84,
    6: 106,
    7: 122,
    8: 152,
    9: 180,
    10: 213,
}

# (ec_codewords_per_block, num_blocks_g1, data_codewords_g1, num_blocks_g2, data_codewords_g2)
_EC_M = {
    1: (10, 1, 16, 0, 0),
    2: (16, 1, 28, 0, 0),
    3: (26, 1, 44, 0, 0),
    4: (18, 2, 32, 0, 0),
    5: (24, 2, 43, 0, 0),
    6: (16, 4, 27, 0, 0),
    7: (18, 4, 31, 0, 0),
    8: (22, 2, 38, 2, 39),
    9: (22, 3, 36, 2, 37),
    10: (26, 4, 43, 1, 44),
}

_ALIGN = {
    1: (),
    2: (6, 18),
    3: (6, 22),
    4: (6, 26),
    5: (6, 30),
    6: (6, 34),
    7: (6, 22, 38),
    8: (6, 24, 42),
    9: (6, 26, 46),
    10: (6, 28, 50),
}

# Format info bits for mask 0..7 at ECC-M (eccl=00 binary → M).
_FORMAT_M = (
    0x5412,
    0x5125,
    0x5E7C,
    0x5B4B,
    0x45F9,
    0x40CE,
    0x4F97,
    0x4AA0,
)

_GF_EXP = [0] * 512
_GF_LOG = [0] * 256


def _init_gf() -> None:
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_init_gf()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator(nsym: int) -> list[int]:
    g = [1]
    for i in range(nsym):
        g = _poly_mul(g, [1, _GF_EXP[i]])
    return g


def _poly_mul(p: list[int], q: list[int]) -> list[int]:
    r = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            r[i + j] ^= _gf_mul(a, b)
    return r


def _rs_encode(data: list[int], nsym: int) -> list[int]:
    gen = _rs_generator(nsym)
    out = [0] * nsym
    for b in data:
        factor = b ^ out[0]
        out = out[1:] + [0]
        for i, g in enumerate(gen[1:]):
            out[i] ^= _gf_mul(g, factor)
    return out


def _choose_version(n: int) -> int:
    for v, cap in _CAPACITY_M.items():
        if n <= cap:
            return v
    raise ValueError(f"data too long for QR versions 1–10 ({n} bytes)")


def _encode_data(data: bytes, version: int) -> list[int]:
    ec_cw, n1, d1, n2, d2 = _EC_M[version]
    total_data = n1 * d1 + n2 * d2
    bits: list[int] = []

    def put(val: int, length: int) -> None:
        for i in range(length - 1, -1, -1):
            bits.append((val >> i) & 1)

    put(0b0100, 4)  # byte mode
    put(len(data), 8 if version < 10 else 16)
    for b in data:
        put(b, 8)

    # terminator
    remain = total_data * 8 - len(bits)
    put(0, min(4, remain))
    while len(bits) % 8:
        bits.append(0)
    pad = (0xEC, 0x11)
    pi = 0
    while len(bits) // 8 < total_data:
        put(pad[pi % 2], 8)
        pi += 1

    codewords = []
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | b
        codewords.append(byte)

    blocks: list[list[int]] = []
    pos = 0
    for _ in range(n1):
        blocks.append(codewords[pos : pos + d1])
        pos += d1
    for _ in range(n2):
        blocks.append(codewords[pos : pos + d2])
        pos += d2

    ec_blocks = [_rs_encode(blk, ec_cw) for blk in blocks]
    result: list[int] = []
    for i in range(max(d1, d2)):
        for blk in blocks:
            if i < len(blk):
                result.append(blk[i])
    for i in range(ec_cw):
        for eb in ec_blocks:
            result.append(eb[i])
    return result


def _matrix_size(version: int) -> int:
    return 17 + 4 * version


def _place_finders(m: list[list[int | None]], size: int) -> None:
    pattern = [
        [1, 1, 1, 1, 1, 1, 1],
        [1, 0, 0, 0, 0, 0, 1],
        [1, 0, 1, 1, 1, 0, 1],
        [1, 0, 1, 1, 1, 0, 1],
        [1, 0, 1, 1, 1, 0, 1],
        [1, 0, 0, 0, 0, 0, 1],
        [1, 1, 1, 1, 1, 1, 1],
    ]

    def draw(r0: int, c0: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = r0 + r, c0 + c
                if 0 <= rr < size and 0 <= cc < size:
                    if 0 <= r < 7 and 0 <= c < 7:
                        m[rr][cc] = pattern[r][c]
                    else:
                        m[rr][cc] = 0

    draw(0, 0)
    draw(0, size - 7)
    draw(size - 7, 0)


def _place_timing(m: list[list[int | None]], size: int) -> None:
    for i in range(size):
        if m[6][i] is None:
            m[6][i] = i % 2 == 0
        if m[i][6] is None:
            m[i][6] = i % 2 == 0


def _place_alignments(m: list[list[int | None]], version: int) -> None:
    pattern = [
        [1, 1, 1, 1, 1],
        [1, 0, 0, 0, 1],
        [1, 0, 1, 0, 1],
        [1, 0, 0, 0, 1],
        [1, 1, 1, 1, 1],
    ]
    size = len(m)
    aligns = _ALIGN[version]
    positions = [(r, c) for r in aligns for c in aligns]
    for ar, ac in positions:
        if (ar <= 8 and ac <= 8) or (ar <= 8 and ac >= size - 9) or (ar >= size - 9 and ac <= 8):
            continue
        for r in range(5):
            for c in range(5):
                m[ar - 2 + r][ac - 2 + c] = pattern[r][c]


def _place_dark(m: list[list[int | None]], size: int) -> None:
    m[size - 8][8] = 1


def _mask_fn(mask: int, r: int, c: int) -> bool:
    if mask == 0:
        return (r + c) % 2 == 0
    if mask == 1:
        return r % 2 == 0
    if mask == 2:
        return c % 3 == 0
    if mask == 3:
        return (r + c) % 3 == 0
    if mask == 4:
        return (r // 2 + c // 3) % 2 == 0
    if mask == 5:
        return (r * c) % 2 + (r * c) % 3 == 0
    if mask == 6:
        return ((r * c) % 2 + (r * c) % 3) % 2 == 0
    return ((r + c) % 2 + (r * c) % 3) % 2 == 0


def _place_data(m: list[list[int | None]], codewords: list[int], version: int, mask: int) -> None:
    size = len(m)
    bits: list[int] = []
    for cw in codewords:
        for i in range(7, -1, -1):
            bits.append((cw >> i) & 1)
    # remainder bits for some versions
    rem = {2: 7, 3: 7, 4: 7, 5: 7, 6: 7}.get(version, 0)
    bits.extend([0] * rem)

    bi = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if m[row][c] is None:
                    bit = bits[bi] if bi < len(bits) else 0
                    bi += 1
                    if _mask_fn(mask, row, c):
                        bit ^= 1
                    m[row][c] = bit
        col -= 2
        upward = not upward


def _place_format(m: list[list[int | None]], mask: int) -> None:
    bits = _FORMAT_M[mask]
    size = len(m)
    coords_a = [
        (8, 0),
        (8, 1),
        (8, 2),
        (8, 3),
        (8, 4),
        (8, 5),
        (8, 7),
        (8, 8),
        (7, 8),
        (5, 8),
        (4, 8),
        (3, 8),
        (2, 8),
        (1, 8),
        (0, 8),
    ]
    coords_b = [
        (size - 1, 8),
        (size - 2, 8),
        (size - 3, 8),
        (size - 4, 8),
        (size - 5, 8),
        (size - 6, 8),
        (size - 7, 8),
        (8, size - 8),
        (8, size - 7),
        (8, size - 6),
        (8, size - 5),
        (8, size - 4),
        (8, size - 3),
        (8, size - 2),
        (8, size - 1),
    ]
    for i in range(15):
        bit = (bits >> (14 - i)) & 1
        r, c = coords_a[i]
        m[r][c] = bit
        r, c = coords_b[i]
        m[r][c] = bit


def _place_version(m: list[list[int | None]], version: int) -> None:
    if version < 7:
        return
    # BCH(18,6) version info
    raw = version << 12
    poly = 0x1F25
    v = raw
    for i in range(5, -1, -1):
        if (v >> (i + 12)) & 1:
            v ^= poly << i
    bits = raw | v
    size = len(m)
    for i in range(18):
        bit = (bits >> i) & 1
        r, c = i // 3, size - 11 + i % 3
        m[r][c] = bit
        m[c][r] = bit


def _penalty(m: list[list[int]]) -> int:
    size = len(m)
    score = 0
    # N1: runs of 5+
    for row in m:
        run = 1
        for i in range(1, size):
            if row[i] == row[i - 1]:
                run += 1
            else:
                if run >= 5:
                    score += run - 2
                run = 1
        if run >= 5:
            score += run - 2
    for c in range(size):
        run = 1
        for r in range(1, size):
            if m[r][c] == m[r - 1][c]:
                run += 1
            else:
                if run >= 5:
                    score += run - 2
                run = 1
        if run >= 5:
            score += run - 2
    # N2: 2x2 blocks
    for r in range(size - 1):
        for c in range(size - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3
    # N4: balance
    dark = sum(sum(row) for row in m)
    total = size * size
    k = abs(dark * 20 - total * 10) // total  # |50% - pct| / 5
    score += k * 10
    return score


def encode_matrix(text: str) -> list[list[int]]:
    """Return a binary matrix (1=dark) for ``text``."""
    data = text.encode("utf-8")
    version = _choose_version(len(data))
    codewords = _encode_data(data, version)
    size = _matrix_size(version)

    best: list[list[int]] | None = None
    best_score = 10**9
    for mask in range(8):
        m: list[list[int | None]] = [[None] * size for _ in range(size)]
        _place_finders(m, size)
        _place_timing(m, size)
        _place_alignments(m, version)
        _place_dark(m, size)
        _place_version(m, version)
        # reserve format areas
        for r, c in [(8, i) for i in range(9)] + [(i, 8) for i in range(9)]:
            if 0 <= r < size and 0 <= c < size and m[r][c] is None:
                m[r][c] = 0
        for i in range(8):
            if m[8][size - 1 - i] is None:
                m[8][size - 1 - i] = 0
            if m[size - 1 - i][8] is None:
                m[size - 1 - i][8] = 0
        _place_data(m, codewords, version, mask)
        _place_format(m, mask)
        _place_version(m, version)
        filled = [[int(cell or 0) for cell in row] for row in m]
        score = _penalty(filled)
        if score < best_score:
            best_score = score
            best = filled
    assert best is not None
    return best


def qr_svg(text: str, *, module_px: int = 4, border: int = 4, dark: str = "#0B1220", light: str = "#ffffff") -> str:
    """Encode ``text`` as a compact inline SVG QR code."""
    matrix = encode_matrix(text)
    n = len(matrix)
    dim = (n + border * 2) * module_px
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" '
        f'width="{dim}" height="{dim}" role="img" aria-label="QR code for report verification">'
        f'<rect width="100%" height="100%" fill="{light}"/>'
    ]
    for r, row in enumerate(matrix):
        for c, val in enumerate(row):
            if val:
                x = (c + border) * module_px
                y = (r + border) * module_px
                parts.append(f'<rect x="{x}" y="{y}" width="{module_px}" height="{module_px}" fill="{dark}"/>')
    parts.append("</svg>")
    return "".join(parts)
