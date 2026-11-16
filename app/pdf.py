"""A small PDF writer, in plain Python: pages with text, lines, rectangles, polylines, filled shapes and images. Nothing else is needed for Netlens' reports.

Text uses the PDF standard fonts Helvetica and Helvetica-Bold with the Windows Latin-1 encoding, so every viewer has them and the file stays small; a character outside
Latin-1 (other scripts) is written as "?" rather than breaking the page. Widths of the characters are built in, so text can be measured and wrapped.

Coordinates are in points (1/72 inch) from the top left of the page; the writer turns them round for PDF, so a report is laid out the way it is read.
"""

from __future__ import annotations

import math
import unicodedata
import zlib
from typing import Iterable, Sequence

A4 = (595.28, 841.89)

# widths of Helvetica and Helvetica-Bold for the characters 32..126, in 1/1000 of the font size
_REGULAR = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
            556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
            1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
            667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
            333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
            556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]
_BOLD = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
         556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
         975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
         667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
         333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
         611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584]
_PUNCT = {"‘": 222, "’": 222, "“": 333, "”": 333, "–": 556, "—": 1000, "…": 1000, "•": 350, "€": 556, " ": 278, "·": 278, "×": 584}


def _plain(ch: str) -> str:
    """The unaccented letter an accented one is measured as."""
    base = unicodedata.normalize("NFD", ch)[:1]
    return base if base and ord(base) < 127 else ch


def char_width(ch: str, bold: bool = False) -> int:
    if ch in _PUNCT:
        return _PUNCT[ch] + (60 if bold and ch in "–" else 0)
    code = ord(ch)
    if code < 32:
        return 0
    if code > 126:
        code = ord(_plain(ch)) if ord(_plain(ch)) < 127 else 556
    return (_BOLD if bold else _REGULAR)[code - 32] if 32 <= code <= 126 else 556


def text_width(text: str, size: float, bold: bool = False) -> float:
    return sum(char_width(c, bold) for c in text) * size / 1000.0


def wrap(text: str, width: float, size: float, bold: bool = False) -> list[str]:
    """Break text into lines no wider than `width`. A word that is wider than a line is cut."""
    lines: list[str] = []
    for paragraph in str(text).split("\n"):
        current = ""
        for word in paragraph.split(" "):
            trial = word if not current else f"{current} {word}"
            if text_width(trial, size, bold) <= width:
                current = trial
                continue
            if current:
                lines.append(current)
            while text_width(word, size, bold) > width and len(word) > 1:     # a long word (an address, a path): cut it where it no longer fits
                cut = len(word)
                while cut > 1 and text_width(word[:cut], size, bold) > width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            current = word
        lines.append(current)
    return lines


def fit(text: str, width: float, size: float, bold: bool = False) -> str:
    """Text shortened with an ellipsis to fit one line."""
    if text_width(text, size, bold) <= width:
        return text
    while text and text_width(text + "…", size, bold) > width:
        text = text[:-1]
    return text + "…"


def _encode(text: str) -> bytes:
    return str(text).replace("−", "-").replace("→", "->").encode("cp1252", "replace")


def _hex(text: str) -> str:
    return "<" + _encode(text).hex() + ">"


def _num(v: float) -> str:
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return s if s not in ("", "-0") else "0"


def _color(c: Sequence[float] | str | None) -> tuple[float, float, float] | None:
    if c is None:
        return None
    if isinstance(c, str):
        c = c.lstrip("#")
        return tuple(int(c[i:i + 2], 16) / 255 for i in (0, 2, 4))        # type: ignore[return-value]
    return tuple(c)                                                         # type: ignore[return-value]


class Page:
    def __init__(self, pdf: "Pdf"):
        self.pdf = pdf
        self.width, self.height = pdf.size
        self.ops: list[str] = []
        self.images: dict[str, int] = {}

    # --- drawing, from the top left
    def _y(self, y: float) -> float:
        return self.height - y

    def _set(self, fill, stroke, width=None, dash=None) -> None:
        f, s = _color(fill), _color(stroke)
        if f:
            self.ops.append(f"{_num(f[0])} {_num(f[1])} {_num(f[2])} rg")
        if s:
            self.ops.append(f"{_num(s[0])} {_num(s[1])} {_num(s[2])} RG")
        if width is not None:
            self.ops.append(f"{_num(width)} w")
        self.ops.append(f"[{' '.join(_num(d) for d in dash)}] 0 d" if dash else "[] 0 d")

    def text(self, x: float, y: float, text: str, size: float = 10, bold: bool = False, color="#1c1f24", align: str = "left", width: float | None = None) -> None:
        """One line of text with its baseline at y. align: left, right or center (about x, or inside `width` from x)."""
        if not text:
            return
        w = text_width(text, size, bold)
        if align == "right":
            x = x + (width if width is not None else 0) - w
        elif align == "center":
            x = x + ((width / 2) if width is not None else 0) - w / 2
        c = _color(color) or (0, 0, 0)
        self.ops.append(f"BT /{'F2' if bold else 'F1'} {_num(size)} Tf {_num(c[0])} {_num(c[1])} {_num(c[2])} rg {_num(x)} {_num(self._y(y))} Td {_hex(text)} Tj ET")

    def rect(self, x: float, y: float, w: float, h: float, fill=None, stroke=None, line_width: float = 0.8) -> None:
        if fill is None and stroke is None:
            return
        self._set(fill, stroke, line_width)
        op = "B" if fill is not None and stroke is not None else "f" if fill is not None else "S"
        self.ops.append(f"{_num(x)} {_num(self._y(y + h))} {_num(w)} {_num(h)} re {op}")

    def rounded(self, x: float, y: float, w: float, h: float, r: float, fill=None, stroke=None, line_width: float = 0.8) -> None:
        """A rectangle with round corners (Bézier curves)."""
        if fill is None and stroke is None:
            return
        r = max(0.0, min(r, w / 2, h / 2))
        k = 0.5523 * r
        y0, y1 = self._y(y + h), self._y(y)
        self._set(fill, stroke, line_width)
        p = [f"{_num(x + r)} {_num(y0)} m", f"{_num(x + w - r)} {_num(y0)} l", f"{_num(x + w - r + k)} {_num(y0)} {_num(x + w)} {_num(y0 + r - k)} {_num(x + w)} {_num(y0 + r)} c",
             f"{_num(x + w)} {_num(y1 - r)} l", f"{_num(x + w)} {_num(y1 - r + k)} {_num(x + w - r + k)} {_num(y1)} {_num(x + w - r)} {_num(y1)} c",
             f"{_num(x + r)} {_num(y1)} l", f"{_num(x + r - k)} {_num(y1)} {_num(x)} {_num(y1 - r + k)} {_num(x)} {_num(y1 - r)} c",
             f"{_num(x)} {_num(y0 + r)} l", f"{_num(x)} {_num(y0 + r - k)} {_num(x + r - k)} {_num(y0)} {_num(x + r)} {_num(y0)} c", "h"]
        self.ops.extend(p)
        self.ops.append("B" if fill is not None and stroke is not None else "f" if fill is not None else "S")

    def line(self, x1: float, y1: float, x2: float, y2: float, color="#cccccc", width: float = 0.6, dash: Sequence[float] | None = None) -> None:
        self._set(None, color, width, dash)
        self.ops.append(f"{_num(x1)} {_num(self._y(y1))} m {_num(x2)} {_num(self._y(y2))} l S")

    def polyline(self, points: Iterable[tuple[float, float]], color="#2563eb", width: float = 1.2) -> None:
        pts = list(points)
        if len(pts) < 2:
            return
        self._set(None, color, width)
        self.ops.append("1 j 1 J")
        self.ops.append(" ".join(f"{_num(x)} {_num(self._y(y))} {'m' if i == 0 else 'l'}" for i, (x, y) in enumerate(pts)) + " S")

    def polygon(self, points: Iterable[tuple[float, float]], fill="#2563eb") -> None:
        pts = list(points)
        if len(pts) < 3:
            return
        self._set(fill, None)
        self.ops.append(" ".join(f"{_num(x)} {_num(self._y(y))} {'m' if i == 0 else 'l'}" for i, (x, y) in enumerate(pts)) + " h f")

    def arc(self, cx: float, cy: float, r: float, start: float, end: float, color="#16a34a", width: float = 6.0) -> None:
        """An arc of a circle, angles in degrees clockwise from twelve o'clock (a score ring)."""
        steps = max(2, int(abs(end - start) / 4))
        pts = [(cx + r * math.sin(math.radians(start + (end - start) * i / steps)), cy - r * math.cos(math.radians(start + (end - start) * i / steps))) for i in range(steps + 1)]
        self._set(None, color, width)
        self.ops.append("1 J 1 j")
        self.ops.append(" ".join(f"{_num(x)} {_num(self._y(y))} {'m' if i == 0 else 'l'}" for i, (x, y) in enumerate(pts)) + " S")

    def circle(self, cx: float, cy: float, r: float, fill="#2563eb", stroke=None) -> None:
        self.rounded(cx - r, cy - r, 2 * r, 2 * r, r, fill=fill, stroke=stroke)

    def image(self, image: dict, x: float, y: float, w: float, h: float) -> None:
        name = self.pdf._image_name(image)
        self.images[name] = self.pdf._images[name]
        self.ops.append(f"q {_num(w)} 0 0 {_num(h)} {_num(x)} {_num(self._y(y + h))} cm /{name} Do Q")


class Pdf:
    def __init__(self, title: str = "", author: str = "Netlens", subject: str = "", size: tuple[float, float] = A4):
        self.size = size
        self.title, self.author, self.subject = title, author, subject
        self.pages: list[Page] = []
        self._images: dict[str, dict] = {}

    def add_page(self) -> Page:
        page = Page(self)
        self.pages.append(page)
        return page

    def _image_name(self, image: dict) -> str:
        for name, known in self._images.items():
            if known is image:
                return name
        name = f"Im{len(self._images) + 1}"
        self._images[name] = image
        return name

    def bytes(self) -> bytes:
        """The finished file. Object numbers: 1 the catalog, 2 the page tree, 3 and 4 the two fonts, then each image (its mask first), then the content and page of every page, last the info record."""
        def stream(dictionary: str, data: bytes, compress: bool = True) -> bytes:
            raw = zlib.compress(data, 6) if compress else data
            extra = " /Filter /FlateDecode" if compress else ""
            return f"<< {dictionary}{extra} /Length {len(raw)} >>\nstream\n".encode() + raw + b"\nendstream"

        objects: dict[int, bytes] = {
            1: b"<< /Type /Catalog /Pages 2 0 R >>",
            3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        }
        nid = 5
        image_ids: dict[str, int] = {}
        for name, image in self._images.items():
            mask_ref = ""
            if image.get("smask"):
                mask = image["smask"]
                objects[nid] = stream(f"/Type /XObject /Subtype /Image /Width {mask['width']} /Height {mask['height']} /ColorSpace /DeviceGray /BitsPerComponent 8", mask["data"])
                mask_ref = f" /SMask {nid} 0 R"
                nid += 1
            head = f"/Type /XObject /Subtype /Image /Width {image['width']} /Height {image['height']} /ColorSpace /{image['colorspace']} /BitsPerComponent 8"
            if image["filter"] == "DCT":
                objects[nid] = stream(head + " /Filter /DCTDecode" + mask_ref, image["data"], compress=False)
            else:
                objects[nid] = stream(head + mask_ref, image["data"])
            image_ids[name] = nid
            nid += 1
        page_ids = []
        for page in self.pages:
            content_id, page_id = nid, nid + 1
            nid += 2
            objects[content_id] = stream("", "\n".join(page.ops).encode("latin-1", "replace"))
            xobjects = " ".join(f"/{n} {image_ids[n]} 0 R" for n in page.images)
            resources = "/Font << /F1 3 0 R /F2 4 0 R >>" + (f" /XObject << {xobjects} >>" if xobjects else "")
            objects[page_id] = f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_num(page.width)} {_num(page.height)}] /Resources << {resources} >> /Contents {content_id} 0 R >>".encode()
            page_ids.append(page_id)
        objects[2] = f"<< /Type /Pages /Kids [{' '.join(f'{p} 0 R' for p in page_ids)}] /Count {len(page_ids)} >>".encode()
        info_id = nid
        objects[info_id] = f"<< /Title {_hex(self.title)} /Author {_hex(self.author)} /Subject {_hex(self.subject)} /Producer {_hex('Netlens')} >>".encode()

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for oid in range(1, info_id + 1):
            offsets.append(len(out))
            out.extend(f"{oid} 0 obj\n".encode() + objects[oid] + b"\nendobj\n")
        xref = len(out)
        out.extend(f"xref\n0 {info_id + 1}\n".encode() + b"0000000000 65535 f \n")
        for off in offsets:
            out.extend(f"{off:010d} 00000 n \n".encode())
        out.extend(f"trailer\n<< /Size {info_id + 1} /Root 1 0 R /Info {info_id} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
        return bytes(out)
