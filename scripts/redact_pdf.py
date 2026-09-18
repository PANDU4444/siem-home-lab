#!/usr/bin/env python3
"""
siem-home-lab :: redact sensitive strings from a PDF write-up.

The addresses that need removing live inside screenshot images, not in the PDF
text layer, so ordinary PDF redaction cannot reach them. Drawing a black box
over the image would not help either: the original pixels would still be in the
file and trivially recoverable.

The only sound approach is to destroy the pixels. For each page:

  1. Render the page to a bitmap at high DPI. (Low DPI silently downsamples the
     embedded screenshots below their native resolution and OCR then misses
     text that is plainly visible in the original.)
  2. OCR it with word-level bounding boxes.
  3. Find sensitive tokens, allowing for OCR splitting one address across
     several "words" - matches are located on the reconstructed line, then
     mapped back to the boxes they overlap.
  4. Paint those boxes solid black.
  5. Replace the whole page with the redacted bitmap.

Pages with nothing to redact are copied through untouched, preserving both file
size and the original quality of the remaining pages. The text layer is handled
separately, before the image pass.

A lesson encoded here: a dotted-quad regex is not enough. Cloud providers put
the address in a hostname (172-236-74-89.ip.linodeusercontent.com), the shell
prompt then shows root@172-236-74-89, and IPv6 is a whole separate namespace.
The first version of this script reported "clean" while all three were still
plainly legible on the page.

Usage:
    python3 scripts/redact_pdf.py in.pdf out.pdf [--dpi 300]
"""

import argparse
import io
import ipaddress
import re
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import fitz  # PyMuPDF
except ImportError:
    sys.exit("PyMuPDF is required: pip install pymupdf")

try:
    from PIL import Image, ImageDraw, ImageFilter
except ImportError:
    sys.exit("Pillow is required: pip install pillow")

CGNAT = ipaddress.ip_network("100.64.0.0/10")  # leakscan:allow

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Cloud providers encode the address into a hostname, so the dotted form is not
# the only way an address appears in a screenshot.
IPV4_DASHED = re.compile(r"\b\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\b")
CLOUD_HOST = re.compile(
    r"\b[\w-]+\.(?:ip\.linodeusercontent\.com|compute\.amazonaws\.com|"
    r"bc\.googleusercontent\.com|cloudapp\.azure\.com)\b")
INSTANCE_URL = re.compile(r"(?:linode\.com/linodes|/instances)/\d{4,}")

# At least two groups plus a tail, so clock times (12:06:16) do not match.
IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}(?::|[0-9a-fA-F]{1,4})"
                  r"(?::[0-9a-fA-F]{1,4}){0,6}\b")

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SECRET = re.compile(  # leakscan:allow
    r"(?i)\b(?:password|passwd|api[_ -]?key|token|secret)\s*[:=]\s*\S{6,}")
CRED_PATH = re.compile(r"/[\w./-]*\.(?:credentials|pem|key|p12|pfx)\b")

# Documentation or public values that must not be redacted.
ALLOW = {"cve@mitre.org", "0.0.0.0", "127.0.0.1", "255.255.255.0",
         "255.255.0.0", "8.8.8.8", "1.1.1.1"}  # leakscan:allow


def is_sensitive_ip(text):
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    if addr.version == 4 and addr in CGNAT:
        return True
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def sensitive_spans(line):
    """Character spans within a line whose pixels must be destroyed."""
    spans = []

    for match in IPV4.finditer(line):
        if match.group(0) not in ALLOW and is_sensitive_ip(match.group(0)):
            spans.append((match.start(), match.end(), match.group(0)))

    for match in IPV4_DASHED.finditer(line):
        dotted = match.group(0).replace("-", ".")
        if dotted not in ALLOW and is_sensitive_ip(dotted):
            spans.append((match.start(), match.end(), dotted))

    for match in IPV6.finditer(line):
        if is_sensitive_ip(match.group(0)):
            spans.append((match.start(), match.end(), match.group(0)))

    for match in CLOUD_HOST.finditer(line):
        spans.append((match.start(), match.end(), match.group(0)))

    for match in INSTANCE_URL.finditer(line):
        spans.append((match.start(), match.end(), "cloud-instance-id"))

    for match in EMAIL.finditer(line):
        if match.group(0).lower() not in ALLOW:
            spans.append((match.start(), match.end(), match.group(0)))

    for match in SECRET.finditer(line):
        spans.append((match.start(), match.end(), "credential-assignment"))

    for match in CRED_PATH.finditer(line):
        spans.append((match.start(), match.end(), "credential-file-path"))

    return spans


def ocr_words(image_path):
    """Return rows of (line_key, text, left, top, width, height)."""
    result = subprocess.run(
        ["tesseract", str(image_path), "stdout", "--psm", "6", "tsv"],
        capture_output=True, text=True)
    rows = []
    for raw in result.stdout.splitlines()[1:]:
        parts = raw.split("\t")
        if len(parts) < 12:
            continue
        text = parts[11].strip()
        if not text:
            continue
        try:
            line_key = tuple(int(parts[i]) for i in (1, 2, 3, 4))
            left, top, width, height = (int(parts[i]) for i in (6, 7, 8, 9))
        except ValueError:
            continue
        rows.append((line_key, text, left, top, width, height))
    return rows


def boxes_to_redact(rows):
    """Group words into lines, find sensitive spans, map back to word boxes."""
    lines = {}
    for line_key, text, left, top, width, height in rows:
        lines.setdefault(line_key, []).append((text, left, top, width, height))

    boxes, hits = [], []
    for words in lines.values():
        offsets, cursor, parts = [], 0, []
        for text, left, top, width, height in words:
            offsets.append((cursor, cursor + len(text), left, top, width, height))
            parts.append(text)
            cursor += len(text) + 1
        line_text = " ".join(parts)

        for start, end, value in sensitive_spans(line_text):
            hits.append(value)
            for w_start, w_end, left, top, width, height in offsets:
                if w_start < end and start < w_end:      # overlap
                    boxes.append((left, top, left + width, top + height))
    return boxes, hits


def redact_text_layer(doc):
    """
    Remove sensitive strings living in the PDF text layer.

    The image pass only rewrites pages whose rendered bitmap shows a hit, so a
    value present only as selectable text would survive it. apply_redactions
    genuinely removes the text rather than drawing over it.
    """
    removed = set()
    for page in doc:
        values = set()
        for line in page.get_text().splitlines():
            for _, _, value in sensitive_spans(line):
                if not value.endswith(("-assignment", "-path", "-id")):
                    values.add(value)
        if not values:
            continue
        marked = False
        for value in values:
            for rect in page.search_for(value):
                page.add_redact_annot(rect, fill=(0, 0, 0))
                marked = True
                removed.add(value)
        if marked:
            page.apply_redactions()
    return removed


def verify(pdf_path):
    """Independently re-check the output: embedded images AND text layer."""
    found = set()
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["pdfimages", "-png", str(pdf_path), str(Path(tmp) / "v")],
                       capture_output=True)
        for image in sorted(Path(tmp).glob("v-*.png")):
            result = subprocess.run(
                ["tesseract", str(image), "stdout", "--psm", "6"],
                capture_output=True, text=True)
            for line in result.stdout.splitlines():
                for _, _, value in sensitive_spans(line):
                    found.add(value)

    doc = fitz.open(pdf_path)
    for page in doc:
        for line in page.get_text().splitlines():
            for _, _, value in sensitive_spans(line):
                found.add(value)
    doc.close()
    return found


def main():
    parser = argparse.ArgumentParser(description="Redact sensitive strings from a PDF")
    parser.add_argument("source")
    parser.add_argument("output")
    parser.add_argument("--dpi", type=int, default=300)
    parser.add_argument("--pad", type=int, default=4,
                        help="pixels of padding around each redaction box")
    args = parser.parse_args()

    src = fitz.open(args.source)
    page_total = src.page_count

    text_removed = redact_text_layer(src)
    if text_removed:
        print("text layer  : removed {}".format(", ".join(sorted(text_removed))))

    out = fitz.open()
    scale = args.dpi / 72.0
    redacted_pages, total_hits = [], []

    blurred_pages = []

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        base_png = tmpdir / "page.png"

        for number in range(page_total):
            page = src[number]

            # --- detect at several scales and union the results ------------
            # One scale is not enough: OCR recognises different strings at
            # different resolutions, so a single pass silently misses some.
            all_boxes, all_hits = [], []
            for factor in (1.0, 1.4):
                probe = tmpdir / "probe.png"
                page.get_pixmap(matrix=fitz.Matrix(scale * factor,
                                                   scale * factor)).save(probe)
                boxes, hits = boxes_to_redact(ocr_words(probe))
                # Map coordinates back to the base render scale.
                all_boxes.extend([(int(x0 / factor), int(y0 / factor),
                                   int(x1 / factor), int(y1 / factor))
                                  for x0, y0, x1, y1 in boxes])
                all_hits.extend(hits)

            if not all_boxes:
                out.insert_pdf(src, from_page=number, to_page=number)
                continue

            page.get_pixmap(matrix=fitz.Matrix(scale, scale)).save(base_png)
            image = Image.open(base_png).convert("RGB")
            draw = ImageDraw.Draw(image)
            for x0, y0, x1, y1 in all_boxes:
                draw.rectangle([x0 - args.pad, y0 - args.pad,
                                x1 + args.pad, y1 + args.pad], fill=(0, 0, 0))

            # --- verify this page, and fall back to blurring if needed -----
            check_png = tmpdir / "check.png"
            image.save(check_png)
            leftover = set()
            for row in ocr_words(check_png):
                pass
            words = ocr_words(check_png)
            lines = {}
            for line_key, text, *_ in words:
                lines.setdefault(line_key, []).append(text)
            for parts in lines.values():
                for _, _, value in sensitive_spans(" ".join(parts)):
                    leftover.add(value)

            if leftover:
                # OCR could not be trusted to find every instance precisely on
                # this page, so blur every screenshot region on it instead.
                for rect in page.get_images(full=True):
                    try:
                        for area in page.get_image_rects(rect[0]):
                            box = (max(int(area.x0 * scale) - 4, 0),
                                   max(int(area.y0 * scale) - 4, 0),
                                   min(int(area.x1 * scale) + 4, image.width),
                                   min(int(area.y1 * scale) + 4, image.height))
                            if box[2] <= box[0] or box[3] <= box[1]:
                                continue
                            region = image.crop(box).filter(
                                ImageFilter.GaussianBlur(radius=14))
                            image.paste(region, box)
                    except Exception:
                        continue
                blurred_pages.append(number + 1)

            buffer = io.BytesIO()
            image.save(buffer, format="JPEG", quality=80, optimize=True)
            buffer.seek(0)

            new_page = out.new_page(width=page.rect.width, height=page.rect.height)
            new_page.insert_image(page.rect, stream=buffer.read())

            redacted_pages.append(number + 1)
            total_hits.extend(all_hits)
            note = "  [blurred: OCR unreliable here]" if leftover else ""
            print("  page {:>3}: {} region(s) -> {}{}".format(
                number + 1, len(all_boxes),
                ", ".join(sorted(set(all_hits)))[:56], note))

    out.save(args.output, garbage=4, deflate=True)
    out.close()
    src.close()

    print("")
    print("pages rewritten : {} of {} ({})".format(
        len(redacted_pages), page_total,
        ", ".join(str(p) for p in redacted_pages) or "none"))
    print("values redacted : {}".format(len(total_hits)))
    print("pages blurred   : {}".format(
        ", ".join(str(p) for p in blurred_pages) or "none"))
    print("output          : {} ({:,} bytes)".format(
        args.output, Path(args.output).stat().st_size))

    print("")
    print("verifying output (re-extract images + re-read text layer)...")
    remaining = verify(args.output)
    if remaining:
        print("  STILL PRESENT: {}".format(", ".join(sorted(remaining))))
        print("  Re-run with a higher --dpi, or extend the patterns.")
        return 1
    print("  clean: nothing sensitive found in the output")
    return 0


if __name__ == "__main__":
    sys.exit(main())
