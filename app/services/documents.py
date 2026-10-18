"""Safe, bounded extraction and rendering of private PDF temporary files."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


class DocumentError(ValueError):
    """A document is unavailable, invalid, or exceeds a configured limit."""


def _fitz():
    try:
        import fitz
    except ImportError as exc:  # pragma: no cover - deployment configuration
        raise DocumentError("PDF support is unavailable; install PyMuPDF") from exc
    return fitz


def _assert_pdf(path: Path, metadata: dict[str, Any]) -> None:
    # MIME metadata is supplied by email and cannot be trusted. Validate bytes too.
    with path.open("rb") as source:
        header = source.read(1024)
    if not header.lstrip().startswith(b"%PDF-"):
        raise DocumentError("temporary file is not a PDF")
    mime = str(metadata.get("mime_type") or "").lower()
    filename = str(metadata.get("filename") or "").lower()
    if mime not in {"application/pdf", "application/x-pdf"} and not filename.endswith(".pdf"):
        raise DocumentError("temporary file is not declared as a PDF")


def _open_pdf(path: Path, metadata: dict[str, Any], max_pages: int):
    _assert_pdf(path, metadata)
    fitz = _fitz()
    try:
        document = fitz.open(path)
    except Exception as exc:
        raise DocumentError("PDF is malformed or cannot be opened") from exc
    if document.needs_pass:
        document.close()
        raise DocumentError("encrypted PDFs are not supported")
    if document.page_count < 1:
        document.close()
        raise DocumentError("PDF has no pages")
    if document.page_count > max_pages:
        document.close()
        raise DocumentError(f"PDF exceeds the configured page limit ({max_pages})")
    return document


def _page_text(page: Any) -> str:
    # sort=True is PyMuPDF's closest reading-order reconstruction for ordinary pages.
    return page.get_text("text", sort=True).strip()


def _ocr_page(page: Any, *, max_pixels: int, timeout_seconds: int) -> str:
    executable = shutil.which("tesseract")
    if not executable:
        raise DocumentError("OCR is unavailable; install Tesseract with fra and eng data")
    rect = page.rect
    scale = min(2.0, (max_pixels / max(rect.width * rect.height, 1)) ** 0.5)
    if scale <= 0:
        raise DocumentError("invalid PDF page dimensions")
    fitz = _fitz()
    pix = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
    try:
        completed = subprocess.run(
            [executable, "stdin", "stdout", "-l", "fra+eng", "--psm", "6"],
            input=pix.tobytes("png"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DocumentError("OCR timed out") from exc
    if completed.returncode:
        raise DocumentError("OCR failed")
    return completed.stdout.decode("utf-8", errors="replace").strip()


def pdf_info(path: Path, metadata: dict[str, Any], settings: Any) -> dict[str, Any]:
    document = _open_pdf(path, metadata, settings.pdf_max_pages)
    try:
        text_pages = 0
        ocr_pages: list[int] = []
        for number in range(document.page_count):
            text = _page_text(document.load_page(number))
            if text:
                text_pages += 1
            else:
                ocr_pages.append(number + 1)
        return {
            "filename": metadata["filename"], "mime_type": metadata["mime_type"],
            "size": metadata["size"], "sha256": metadata["sha256"],
            "expires_at": metadata["expires_at"], "total_pages": document.page_count,
            "has_text_layer": bool(text_pages), "pages_requiring_ocr": ocr_pages,
        }
    finally:
        document.close()


def read_pdf_pages(path: Path, metadata: dict[str, Any], settings: Any, start_page: int, end_page: int, max_chars: int, ocr: str) -> dict[str, Any]:
    if ocr not in {"auto", "never", "always"}:
        raise DocumentError("ocr must be auto, never, or always")
    if start_page < 1 or end_page < start_page:
        raise DocumentError("invalid page range")
    if max_chars < 1 or max_chars > settings.pdf_max_chars:
        raise DocumentError(f"max_chars must be between 1 and {settings.pdf_max_chars}")
    document = _open_pdf(path, metadata, settings.pdf_max_pages)
    try:
        if start_page > document.page_count:
            raise DocumentError("page is outside the PDF")
        end_page = min(end_page, document.page_count)
        remaining = max_chars
        pages: list[dict[str, Any]] = []
        truncated = False
        for number in range(start_page, end_page + 1):
            page = document.load_page(number - 1)
            text = _page_text(page)
            method = "text"
            if ocr == "always" or (ocr == "auto" and len(text) < settings.pdf_ocr_min_text_chars):
                ocr_text = _ocr_page(page, max_pixels=settings.pdf_render_max_pixels, timeout_seconds=settings.pdf_ocr_timeout_seconds)
                if ocr == "always" or ocr_text:
                    text, method = ocr_text, "ocr"
            page_truncated = len(text) > remaining
            if page_truncated:
                text = text[:remaining]
                truncated = True
            pages.append({"page": number, "method": method, "text": text, "truncated": page_truncated})
            remaining -= len(text)
            if remaining <= 0:
                truncated = truncated or number < end_page
                break
        last_page = pages[-1]["page"]
        return {
            "filename": metadata["filename"], "sha256": metadata["sha256"],
            "total_pages": document.page_count, "pages": pages, "truncated": truncated,
            "next_page": last_page + 1 if truncated and last_page < document.page_count else None,
        }
    finally:
        document.close()


def render_pdf_page(path: Path, metadata: dict[str, Any], settings: Any, page_number: int) -> tuple[bytes, dict[str, Any]]:
    document = _open_pdf(path, metadata, settings.pdf_max_pages)
    try:
        if page_number < 1 or page_number > document.page_count:
            raise DocumentError("page is outside the PDF")
        page = document.load_page(page_number - 1)
        rect = page.rect
        scale = min(settings.pdf_render_scale, (settings.pdf_render_max_pixels / max(rect.width * rect.height, 1)) ** 0.5)
        fitz = _fitz()
        pix = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
        image = pix.tobytes("png")
        if len(image) > settings.pdf_render_max_bytes:
            raise DocumentError("rendered PDF page exceeds configured image size limit")
        return image, {"filename": metadata["filename"], "sha256": metadata["sha256"], "page": page_number, "total_pages": document.page_count, "mime_type": "image/png"}
    finally:
        document.close()
