from datetime import datetime, timedelta, timezone

import pytest

from app.config import Settings
from app.services.ubl import parse_ubl_invoice
from app.temp_files import cleanup_expired_temporary_files, resolve_temporary_file, store_temporary_file


def test_private_temporary_file_has_metadata_and_expires(tmp_path):
    settings = Settings(_env_file=None, temporary_file_dir=tmp_path, temporary_file_ttl_minutes=1)
    item = store_temporary_file(settings, b"%PDF-test", "../invoice.pdf", "application/pdf")
    path, metadata = resolve_temporary_file(settings, item["temporary_file_id"])
    assert path.read_bytes() == b"%PDF-test"
    assert metadata["filename"] == "invoice.pdf"
    assert len(metadata["sha256"]) == 64
    expired = datetime.now(timezone.utc) + timedelta(minutes=2)
    assert cleanup_expired_temporary_files(settings, now=expired) == 1
    with pytest.raises(ValueError, match="not found"):
        resolve_temporary_file(settings, item["temporary_file_id"])


def test_temporary_file_rejects_size_and_blocked_type(tmp_path):
    settings = Settings(_env_file=None, temporary_file_dir=tmp_path, temporary_file_max_bytes=2, blocked_attachment_types=["application/x-danger"])
    with pytest.raises(ValueError, match="limit"):
        store_temporary_file(settings, b"123", "a.pdf", "application/pdf")
    with pytest.raises(ValueError, match="blocked"):
        store_temporary_file(settings, b"x", "a.bin", "application/x-danger")


def test_parse_ubl_invoice_without_invented_fields():
    xml = b'''<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"><ID>INV-42</ID><IssueDate>2026-08-01</IssueDate><DocumentCurrencyCode>EUR</DocumentCurrencyCode><AccountingSupplierParty><Party><PartyName><Name>Acme</Name></PartyName><PartyTaxScheme><CompanyID>BE0123</CompanyID></PartyTaxScheme></Party></AccountingSupplierParty><LegalMonetaryTotal><TaxExclusiveAmount>100.00</TaxExclusiveAmount><TaxInclusiveAmount>121.00</TaxInclusiveAmount><PayableAmount>121.00</PayableAmount></LegalMonetaryTotal><TaxTotal><TaxAmount>21.00</TaxAmount></TaxTotal><InvoiceLine><ID>1</ID><InvoicedQuantity>2</InvoicedQuantity><LineExtensionAmount>100.00</LineExtensionAmount><Item><Description>Service</Description></Item><Price><PriceAmount>50.00</PriceAmount></Price></InvoiceLine></Invoice>'''
    parsed = parse_ubl_invoice(xml)
    assert parsed["invoice_number"] == "INV-42"
    assert parsed["supplier"]["name"] == "Acme"
    assert parsed["tax_amount"] == "21.00"
    assert parsed["lines"][0]["unit_price"] == "50.00"
    assert parse_ubl_invoice(b"<not-an-invoice/>") is None
