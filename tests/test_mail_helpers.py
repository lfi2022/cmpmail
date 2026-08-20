from email.message import EmailMessage

import pytest

from app.services.mail import (
    build_reply_headers,
    canonical_mailbox,
    mailbox_dict,
    normalize_message_id,
    parse_references,
    reply_all_recipients,
)


def test_mailbox_uses_real_delimiter():
    item = mailbox_dict(("\\Archive",), ".", "INBOX.Clients.Factures")
    assert item["delimiter"] == "."
    assert item["display_name"] == "Factures"
    assert item["canonical_name"] == "INBOX.Clients.Factures"
    assert item["special_use"] == "archive"


def test_resolver_exact_and_friendly():
    boxes = [
        mailbox_dict((), "/", "INBOX/fournisseurs/Factures"),
        mailbox_dict((), "/", "INBOX/Archive"),
    ]
    assert canonical_mailbox(boxes, "Factures") == "INBOX/fournisseurs/Factures"
    assert canonical_mailbox(boxes, "inbox/archive") == "INBOX/Archive"


def test_resolver_rejects_ambiguity():
    boxes = [
        mailbox_dict((), "/", "INBOX/A/Factures"),
        mailbox_dict((), "/", "INBOX/B/Factures"),
    ]
    with pytest.raises(ValueError, match="ambiguous"):
        canonical_mailbox(boxes, "Factures")


def test_message_id_and_thread_headers():
    parent = EmailMessage()
    parent["Message-ID"] = "<parent@example.test>"
    parent["References"] = "<root@example.test>"
    in_reply_to, refs = build_reply_headers(parent)
    assert in_reply_to == "<parent@example.test>"
    assert parse_references(refs) == ["<root@example.test>", "<parent@example.test>"]
    assert normalize_message_id("noise <x@y.test> noise") == "<x@y.test>"


def test_reply_all_excludes_local_and_deduplicates():
    parent = EmailMessage()
    parent["From"] = "Alice <alice@example.test>"
    parent["To"] = "me@example.test, Bob <bob@example.test>"
    parent["Cc"] = "ALICE@example.test, Carol <carol@example.test>"
    to, cc = reply_all_recipients(parent, "me@example.test")
    assert to == ["alice@example.test", "bob@example.test"]
    assert cc == ["carol@example.test"]
