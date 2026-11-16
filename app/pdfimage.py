"""Pictures for the PDF writer (app/pdf.py): a logo as JPEG or PNG. No imaging library is needed.

JPEG goes into the file as it is (the PDF viewer decodes it). PNG is decoded here (8-bit grey, grey with alpha, RGB, RGBA, and palette images of 1 to 8 bits; 16-bit
images are read at 8 bits; not interlaced) and written again as a plain image with a separate transparency mask, which is what PDF wants.
"""

from __future__ import annotations

import struct
import zlib

MAX_BYTES = 400_000
MAX_PIXELS = 600_000
PNG = b"\x89PNG\r\n\x1a\n"


class ImageError(ValueError):
    pass


def sniff(data: bytes) -> str | None:
    if data[:8] == PNG:
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    return None


def load(data: bytes) -> dict:
    """The picture as the writer wants it: {"width", "height", "colorspace", "filter", "data", "smask"}. Raises ImageError with a sentence for the person."""
    if len(data) > MAX_BYTES:
        raise ImageError(f"the picture is larger than {MAX_BYTES // 1000} KB")
    kind = sniff(data)
    if kind is None:
        raise ImageError("use a PNG or a JPEG picture")
    try:
        return _jpeg(data) if kind == "jpeg" else _png(data)
    except (struct.error, IndexError, KeyError, MemoryError):               # a file that is cut off or garbled
        raise ImageError("that is not a readable " + ("JPEG" if kind == "jpeg" else "PNG")) from None


def _jpeg(data: bytes) -> dict:
    i = 2
    while i + 4 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        length = struct.unpack(">H", data[i + 2:i + 4])[0]
        if marker in (0xC0, 0xC1, 0xC2):
            precision, height, width, components = data[i + 4], *struct.unpack(">HH", data[i + 5:i + 9]), data[i + 9]
            if precision != 8:
                raise ImageError("the JPEG must have 8 bits per colour")
            if components not in (1, 3):
                raise ImageError("the JPEG must be grey or RGB (not CMYK)")
            if width * height > MAX_PIXELS * 4:
                raise ImageError("the picture is too large")
            return {"width": width, "height": height, "colorspace": "DeviceGray" if components == 1 else "DeviceRGB", "filter": "DCT", "data": data, "smask": None}
        i += 2 + length
    raise ImageError("that is not a readable JPEG")


def _chunks(data: bytes):
    i = 8
    while i + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[i:i + 8])
        yield kind, data[i + 8:i + 8 + length]
        i += 12 + length
        if kind == b"IEND":
            return


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    return a if pa <= pb and pa <= pc else b if pb <= pc else c


def _unfilter(raw: bytes, height: int, row_bytes: int, bpp: int) -> list[bytearray]:
    rows: list[bytearray] = []
    prev = bytearray(row_bytes)
    pos = 0
    for _ in range(height):
        kind = raw[pos]
        line = bytearray(raw[pos + 1:pos + 1 + row_bytes])
        pos += 1 + row_bytes
        if len(line) != row_bytes:
            raise ImageError("the PNG is damaged")
        if kind == 1:
            for x in range(bpp, row_bytes):
                line[x] = (line[x] + line[x - bpp]) & 255
        elif kind == 2:
            for x in range(row_bytes):
                line[x] = (line[x] + prev[x]) & 255
        elif kind == 3:
            for x in range(row_bytes):
                left = line[x - bpp] if x >= bpp else 0
                line[x] = (line[x] + ((left + prev[x]) >> 1)) & 255
        elif kind == 4:
            for x in range(row_bytes):
                left = line[x - bpp] if x >= bpp else 0
                upper_left = prev[x - bpp] if x >= bpp else 0
                line[x] = (line[x] + _paeth(left, prev[x], upper_left)) & 255
        elif kind != 0:
            raise ImageError("the PNG is damaged")
        rows.append(line)
        prev = line
    return rows


def _png(data: bytes) -> dict:
    header = palette = trns = None
    idat = bytearray()
    for kind, body in _chunks(data):
        if kind == b"IHDR":
            header = struct.unpack(">IIBBBBB", body[:13])
        elif kind == b"PLTE":
            palette = body
        elif kind == b"tRNS":
            trns = body
        elif kind == b"IDAT":
            idat.extend(body)
    if header is None or not idat:
        raise ImageError("that is not a readable PNG")
    width, height, depth, color, _compression, _filter, interlace = header
    if interlace:
        raise ImageError("save the PNG without interlacing")
    if width * height > MAX_PIXELS:
        raise ImageError(f"the picture is larger than {MAX_PIXELS // 1000} thousand pixels: make it smaller")
    if color not in (0, 2, 3, 4, 6) or depth not in (1, 2, 4, 8, 16) or (color in (2, 4, 6) and depth < 8) or (color == 3 and depth == 16):
        raise ImageError("this kind of PNG is not supported: save it as an ordinary 8-bit PNG")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    bits = depth * channels
    row_bytes = (width * bits + 7) // 8
    bpp = max(1, bits // 8)
    try:
        raw = zlib.decompress(bytes(idat))
    except zlib.error:
        raise ImageError("the PNG is damaged") from None
    if len(raw) < height * (row_bytes + 1):
        raise ImageError("the PNG is damaged")
    rows = _unfilter(raw, height, row_bytes, bpp)

    def samples(line: bytearray) -> list[int]:
        """The values of one row, one per channel and pixel, scaled to 0..255 (palette indexes stay as they are)."""
        if depth == 8:
            return list(line)
        if depth == 16:
            return list(line[0::2])
        per = 8 // depth
        mask = (1 << depth) - 1
        out = []
        for x in range(width * channels):
            byte = line[x // per]
            shift = 8 - depth * (x % per + 1)
            v = (byte >> shift) & mask
            out.append(v if color == 3 else v * 255 // mask)
        return out

    rgb = bytearray()
    alpha = bytearray()
    has_alpha = color in (4, 6) or trns is not None
    pal = [tuple(palette[i:i + 3]) for i in range(0, len(palette or b""), 3)]
    gray_key = struct.unpack(">H", trns[:2])[0] if (trns and color == 0 and len(trns) >= 2) else None
    for line in rows:
        s = samples(line)
        if color == 6:
            for x in range(0, len(s), 4):
                rgb.extend(s[x:x + 3])
                alpha.append(s[x + 3])
        elif color == 4:
            for x in range(0, len(s), 2):
                rgb.extend((s[x], s[x], s[x]))
                alpha.append(s[x + 1])
        elif color == 2:
            rgb.extend(s)
        elif color == 3:
            for v in s:
                rgb.extend(pal[v] if v < len(pal) else (0, 0, 0))
                alpha.append(trns[v] if trns and v < len(trns) else 255)
        else:
            for v in s:
                rgb.extend((v, v, v))
                if has_alpha:
                    alpha.append(0 if (gray_key is not None and v == (gray_key if depth == 8 else gray_key >> 8)) else 255)
    smask = {"width": width, "height": height, "data": bytes(alpha)} if has_alpha and any(a != 255 for a in alpha) else None
    return {"width": width, "height": height, "colorspace": "DeviceRGB", "filter": "Flate", "data": bytes(rgb), "smask": smask}
