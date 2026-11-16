"""The PDF writer and its picture reader."""
import re
import struct
import zlib

import pytest

from app import pdf, pdfimage


def objects(data: bytes) -> dict[int, bytes]:
    """The objects of a file, found through its cross-reference table (so a wrong offset fails here)."""
    assert data.startswith(b"%PDF-1.4") and data.rstrip().endswith(b"%%EOF")
    start = int(re.search(rb"startxref\n(\d+)\n%%EOF", data).group(1))
    assert data[start:start + 4] == b"xref"
    head = data[start:].split(b"\n")
    count = int(head[1].split()[1])
    out = {}
    for n in range(1, count):
        offset = int(head[2 + n][:10])
        assert data[offset:].startswith(f"{n} 0 obj\n".encode()), f"object {n} is not where the table says"
        out[n] = data[offset:data.index(b"endobj", offset)]
    return out


def content_of(page_object: bytes, objs: dict[int, bytes]) -> bytes:
    ref = int(re.search(rb"/Contents (\d+) 0 R", page_object).group(1))
    body = objs[ref]
    stream = body[body.index(b"stream\n") + 7:body.rindex(b"\nendstream")]
    return zlib.decompress(stream)


def png(width, height, color, depth=8, pixels=None, filters=None, palette=None, trns=None, interlace=0):
    """A PNG made here, with every row filtered the way `filters` says (0 to 4), to check the reader's unfiltering."""
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    row_bytes = (width * channels * depth + 7) // 8
    rows = [bytes(pixels[y * row_bytes:(y + 1) * row_bytes]) for y in range(height)]
    bpp = max(1, channels * depth // 8)
    raw = bytearray()
    prev = bytes(row_bytes)
    for y, row in enumerate(rows):
        kind = (filters or [0])[y % len(filters or [0])]
        raw.append(kind)
        for x in range(row_bytes):
            a = row[x - bpp] if x >= bpp else 0
            b = prev[x]
            c = prev[x - bpp] if x >= bpp else 0
            if kind == 0:
                v = row[x]
            elif kind == 1:
                v = row[x] - a
            elif kind == 2:
                v = row[x] - b
            elif kind == 3:
                v = row[x] - ((a + b) >> 1)
            else:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                v = row[x] - (a if pa <= pb and pa <= pc else b if pb <= pc else c)
            raw.append(v & 255)
        prev = row

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)

    out = pdfimage.PNG + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, depth, color, 0, 0, interlace))
    if palette:
        out += chunk(b"PLTE", bytes(palette))
    if trns:
        out += chunk(b"tRNS", bytes(trns))
    return out + chunk(b"IDAT", zlib.compress(bytes(raw))) + chunk(b"IEND", b"")


def test_a_file_is_well_formed_and_holds_what_was_drawn():
    doc = pdf.Pdf(title="Report é", author="Anna")
    page = doc.add_page()
    page.text(50, 60, "Hello, “world” — é ✓", 14, bold=True)
    page.rect(50, 80, 100, 40, fill="#2563eb", stroke="#000000")
    page.line(50, 140, 300, 140, dash=(3, 2))
    page.polyline([(50, 200), (100, 160), (150, 190)])
    page.arc(300, 200, 30, 0, 270)
    page.rounded(320, 80, 100, 40, 6, fill="#eeeeee")
    doc.add_page().text(50, 50, "Page two")
    data = doc.bytes()
    objs = objects(data)
    pages = [o for o in objs.values() if b"/Type /Page " in o]
    assert len(pages) == 2 and b"/Count 2" in objs[2]
    first = content_of(pages[0], objs).decode("latin-1")
    assert "BT /F2 14 Tf" in first and " re B" in first and "[3 2] 0 d" in first
    assert bytes.fromhex(re.search(r"<([0-9a-f]+)> Tj", first).group(1)).decode("cp1252") == "Hello, “world” — é ?"           # a character Latin-1 lacks is a question mark
    assert b"/Title <" in objs[max(objs)] and bytes.fromhex(re.search(rb"/Title <([0-9a-f]+)>", objs[max(objs)]).group(1).decode()).decode("cp1252") == "Report é"


def test_text_is_measured_with_the_widths_of_helvetica_and_wrapped_to_fit():
    assert pdf.text_width("Hello", 10) == pytest.approx(22.78)                      # H 722 + e 556 + l 222 + l 222 + o 556
    assert pdf.text_width("Hello", 10, bold=True) > pdf.text_width("Hello", 10)
    assert pdf.text_width("é", 10) == pdf.text_width("e", 10)                       # an accented letter is as wide as the letter
    lines = pdf.wrap("one two three four five six seven eight", 60, 10)
    assert all(pdf.text_width(line, 10) <= 60 for line in lines) and " ".join(lines) == "one two three four five six seven eight"
    cut = pdf.wrap("x" * 80, 50, 10)
    assert len(cut) > 1 and all(pdf.text_width(line, 10) <= 50 for line in cut) and "".join(cut) == "x" * 80      # a word wider than a line is cut
    assert pdf.wrap("a\nb", 100, 10) == ["a", "b"] and pdf.fit("short", 100, 10) == "short"
    assert pdf.fit("a very long line that cannot fit", 60, 10).endswith("…") and pdf.text_width(pdf.fit("a very long line that cannot fit", 60, 10), 10) <= 60


def test_a_png_is_decoded_with_every_filter():
    pixels = bytes((x * 37 + y * 11 + c * 5) & 255 for y in range(6) for x in range(5) for c in range(3))
    for filters in ([0], [1], [2], [3], [4], [0, 1, 2, 3, 4]):
        image = pdfimage.load(png(5, 6, 2, pixels=pixels, filters=filters))
        assert (image["width"], image["height"], image["colorspace"], image["filter"]) == (5, 6, "DeviceRGB", "Flate") and image["smask"] is None
        assert image["data"] == pixels, filters


def test_transparency_greys_palettes_and_16_bit_pictures():
    rgba = bytes([255, 0, 0, 255, 0, 255, 0, 0, 0, 0, 255, 128, 9, 9, 9, 255])
    image = pdfimage.load(png(2, 2, 6, pixels=rgba, filters=[4, 1]))
    assert image["data"] == bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 9, 9, 9]) and image["smask"]["data"] == bytes([255, 0, 128, 255])
    opaque = pdfimage.load(png(2, 1, 6, pixels=bytes([1, 2, 3, 255, 4, 5, 6, 255])))
    assert opaque["smask"] is None                                                # fully opaque: no mask needed
    grey_alpha = pdfimage.load(png(2, 1, 4, pixels=bytes([10, 255, 200, 0])))
    assert grey_alpha["data"] == bytes([10, 10, 10, 200, 200, 200]) and grey_alpha["smask"]["data"] == bytes([255, 0])
    two_bit = pdfimage.load(png(4, 1, 3, depth=2, pixels=bytes([0b00011011]), palette=[255, 0, 0, 0, 255, 0, 0, 0, 255, 9, 9, 9], trns=[255, 128]))
    assert two_bit["data"] == bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 9, 9, 9]) and two_bit["smask"]["data"] == bytes([255, 128, 255, 255])
    sixteen = pdfimage.load(png(2, 1, 0, depth=16, pixels=bytes([0xAA, 0x01, 0x33, 0xFF])))
    assert sixteen["data"] == bytes([0xAA] * 3 + [0x33] * 3)
    one_bit = pdfimage.load(png(8, 1, 0, depth=1, pixels=bytes([0b10100000])))
    assert one_bit["data"][:6] == bytes([255, 255, 255, 0, 0, 0])


def test_a_jpeg_goes_in_as_it_is_and_unusable_pictures_are_refused():
    jpeg = b"\xff\xd8\xff\xe0\x00\x04ab\xff\xc0\x00\x11\x08\x00\x20\x00\x40\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01\xff\xd9"
    image = pdfimage.load(jpeg)
    assert (image["width"], image["height"], image["colorspace"], image["filter"], image["data"]) == (64, 32, "DeviceRGB", "DCT", jpeg)
    for bad, message in ((b"GIF89a....", "PNG or a JPEG"), (b"\xff\xd8\xff\xe0\x00\x04ab\xff\xd9", "readable JPEG"), (png(2, 2, 2, pixels=bytes(12), interlace=1), "interlacing"),
                         (pdfimage.PNG + b"junk", "readable PNG"), (b"\x89PNG\r\n\x1a\n" + bytes(500_000), "larger")):
        with pytest.raises(pdfimage.ImageError, match=message):
            pdfimage.load(bad)
    big = pdfimage.PNG + struct.pack(">I", 13) + b"IHDR" + struct.pack(">IIBBBBB", 1000, 1000, 8, 0, 0, 0, 0) + b"\0\0\0\0" + struct.pack(">I", 4) + b"IDAT" + b"abcd" + b"\0\0\0\0"
    with pytest.raises(pdfimage.ImageError, match="thousand pixels"):
        pdfimage.load(big)


def test_a_picture_with_transparency_is_embedded_with_its_mask():
    doc = pdf.Pdf()
    page = doc.add_page()
    logo = pdfimage.load(png(2, 2, 6, pixels=bytes([255, 0, 0, 255, 0, 255, 0, 0, 0, 0, 255, 128, 9, 9, 9, 255])))
    page.image(logo, 40, 40, 100, 50)
    page.image(logo, 200, 40, 40, 20)                                              # the same picture twice is stored once
    objs = objects(doc.bytes())
    images = [o for o in objs.values() if b"/Subtype /Image" in o]
    assert len(images) == 2 and any(b"/SMask" in o for o in images) and any(b"/DeviceGray" in o for o in images)
    assert b"/Im1 Do" in content_of([o for o in objs.values() if b"/Type /Page " in o][0], objs)
