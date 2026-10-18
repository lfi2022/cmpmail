import fitz
import pytest

from app.config import Settings
from app.services.documents import DocumentError, pdf_info, read_pdf_pages, render_pdf_page
from app.temp_files import cleanup_expired_temporary_files, resolve_temporary_file, store_temporary_file


def _pdf_bytes(pages: list[str]) -> bytes:
    document = fitz.open()
    for text in pages:
        page = document.new_page()
        page.insert_text((72, 72), text)
    data = document.tobytes()
    document.close()
    return data


def _stored_pdf(settings, content):
    stored = store_temporary_file(settings, content, "invoice.pdf", "application/pdf")
    return (*resolve_temporary_file(settings, stored["temporary_file_id"]), stored)


def test_reads_info_pages_truncation_and_render(tmp_path):
    settings = Settings(_env_file=None, temporary_file_dir=tmp_path, pdf_max_chars=100, pdf_render_max_bytes=1_000_000)
    path, metadata, _ = _stored_pdf(settings, _pdf_bytes(["Invoice one", "Invoice two"]))
    info = pdf_info(path, metadata, settings)
    assert info["total_pages"] == 2 and info["has_text_layer"]
    read = read_pdf_pages(path, metadata, settings, 1, 2, 100, "never")
    assert [item["text"] for item in read["pages"]] == ["Invoice one", "Invoice two"]
    image, details = render_pdf_page(path, metadata, settings, 1)
    assert image.startswith(b"\x89PNG") and details["page"] == 1
    short = read_pdf_pages(path, metadata, settings, 1, 2, 3, "never")
    assert short["truncated"] and short["next_page"] == 2


def test_rejects_non_pdf_corrupt_encrypted_and_expired_files(tmp_path):
    settings = Settings(_env_file=None, temporary_file_dir=tmp_path)
    bad_path, bad_meta, _ = _stored_pdf(settings, b"not a pdf")
    with pytest.raises(DocumentError, match="not a PDF"):
        pdf_info(bad_path, bad_meta, settings)
    corrupt_path, corrupt_meta, _ = _stored_pdf(settings, b"%PDF-1.7 broken")
    with pytest.raises(DocumentError, match="malformed"):
        pdf_info(corrupt_path, corrupt_meta, settings)
    encrypted = fitz.open()
    encrypted.new_page()
    encrypted_data = encrypted.tobytes(encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw="owner", user_pw="user")
    encrypted.close()
    path, metadata, stored = _stored_pdf(settings, encrypted_data)
    with pytest.raises(DocumentError, match="encrypted"):
        pdf_info(path, metadata, settings)
    from datetime import datetime, timedelta, timezone
    cleanup_expired_temporary_files(settings, now=datetime.now(timezone.utc) + timedelta(minutes=31))
    with pytest.raises(ValueError, match="not found"):
        resolve_temporary_file(settings, stored["temporary_file_id"])
