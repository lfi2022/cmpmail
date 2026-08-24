from __future__ import annotations

import xml.etree.ElementTree as ET
from decimal import Decimal, InvalidOperation
from typing import Any


def _name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _first(parent: ET.Element, name: str) -> ET.Element | None:
    return next((item for item in parent.iter() if _name(item) == name), None)


def _text(parent: ET.Element, name: str) -> str | None:
    item = _first(parent, name)
    return item.text.strip() if item is not None and item.text else None


def _decimal(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return format(Decimal(value), "f")
    except (InvalidOperation, ValueError):
        return value


def parse_ubl_invoice(content: bytes) -> dict[str, Any] | None:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return None
    if _name(root) not in {"Invoice", "CreditNote"}:
        return None
    supplier = _first(root, "AccountingSupplierParty")
    customer = _first(root, "AccountingCustomerParty")
    def party(value: ET.Element | None) -> dict[str, Any] | None:
        if value is None: return None
        return {"name": _text(value, "Name"), "endpoint_id": _text(value, "EndpointID"), "vat_id": _text(value, "CompanyID")}
    lines = []
    for item in root.iter():
        if _name(item) not in {"InvoiceLine", "CreditNoteLine"}: continue
        lines.append({"id": _text(item, "ID"), "description": _text(item, "Description"), "quantity": _decimal(_text(item, "InvoicedQuantity") or _text(item, "CreditedQuantity")), "unit_price": _decimal(_text(item, "PriceAmount")), "line_extension_amount": _decimal(_text(item, "LineExtensionAmount")), "tax_percent": _decimal(_text(item, "Percent"))})
    legal = _first(root, "LegalMonetaryTotal")
    tax_total = _first(root, "TaxTotal")
    return {"document_type": _name(root), "invoice_number": _text(root, "ID"), "issue_date": _text(root, "IssueDate"), "due_date": _text(root, "DueDate"), "currency": _text(root, "DocumentCurrencyCode"), "supplier": party(supplier), "customer": party(customer), "order_reference": _text(_first(root, "OrderReference") or root, "ID") if _first(root, "OrderReference") is not None else None, "tax_exclusive_amount": _decimal(_text(legal, "TaxExclusiveAmount")) if legal is not None else None, "tax_amount": _decimal(_text(tax_total, "TaxAmount")) if tax_total is not None else None, "tax_inclusive_amount": _decimal(_text(legal, "TaxInclusiveAmount")) if legal is not None else None, "payable_amount": _decimal(_text(legal, "PayableAmount")) if legal is not None else None, "lines": lines}
