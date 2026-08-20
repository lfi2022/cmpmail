import asyncio
import base64
import email
import html
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage, Message
from email.utils import format_datetime, getaddresses, make_msgid, parsedate_to_datetime
from typing import Any, Iterator

import aiosmtplib
import bleach
from imapclient import IMAPClient

from app.config import Settings
from app.models import MailAccount
from app.security import CredentialCipher, safe_destination, sanitize_filename

SPECIAL_FLAGS = {
    "\\Sent": "sent",
    "\\Drafts": "drafts",
    "\\Trash": "trash",
    "\\Archive": "archive",
    "\\Junk": "junk",
}
SYSTEM_FLAGS = {"\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft"}


def result(data: Any = None, *, warnings: list[str] | None = None) -> dict[str, Any]:
    return {"success": True, "data": data, "warnings": warnings or [], "errors": []}


def failure(error: str, *, data: Any = None) -> dict[str, Any]:
    return {"success": False, "data": data, "warnings": [], "errors": [error]}


def partial(
    data: Any, processed: int, failed: int, errors: list[str]
) -> dict[str, Any]:
    return {
        "success": False,
        "partial": True,
        "processed": processed,
        "failed": failed,
        "data": data,
        "warnings": [],
        "errors": errors,
    }


def decode_text(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def normalize_message_id(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"<[^<>\s]+>", value)
    return match.group(0) if match else value.strip()


def parse_references(value: str | None) -> list[str]:
    return re.findall(r"<[^<>\s]+>", value or "")


def build_reply_headers(parent: Message) -> tuple[str | None, str]:
    parent_id = normalize_message_id(parent.get("Message-ID"))
    refs = parse_references(parent.get("References"))
    if parent_id and parent_id not in refs:
        refs.append(parent_id)
    return parent_id, " ".join(refs)


def reply_all_recipients(
    parent: Message, local_address: str
) -> tuple[list[str], list[str]]:
    reply_to = parent.get("Reply-To") or parent.get("From") or ""
    to_values = [reply_to, parent.get("To", "")]
    cc_values = [parent.get("Cc", "")]
    local = local_address.casefold()
    seen: set[str] = set()

    def unique(values: list[str]) -> list[str]:
        output = []
        for _, address in getaddresses(values):
            key = address.casefold()
            if address and key != local and key not in seen:
                seen.add(key)
                output.append(address)
        return output

    return unique(to_values), unique(cc_values)


def canonical_mailbox(mailboxes: list[dict[str, Any]], value: str) -> str:
    exact = [m for m in mailboxes if m["canonical_name"].casefold() == value.casefold()]
    if len(exact) == 1:
        return exact[0]["canonical_name"]
    friendly = [
        m for m in mailboxes if m["display_name"].casefold() == value.casefold()
    ]
    if len(friendly) == 1:
        return friendly[0]["canonical_name"]
    suffix = [
        m
        for m in mailboxes
        if m["canonical_name"].casefold().endswith(value.casefold())
    ]
    if len(suffix) == 1:
        return suffix[0]["canonical_name"]
    if len(friendly) + len(suffix) > 1:
        raise ValueError(f"Mailbox name is ambiguous: {value}")
    raise ValueError(f"Mailbox not found: {value}")


def mailbox_dict(
    flags: tuple[bytes | str, ...], delimiter: bytes | str | None, name: str
) -> dict[str, Any]:
    decoded_flags = [f.decode() if isinstance(f, bytes) else str(f) for f in flags]
    delim = delimiter.decode() if isinstance(delimiter, bytes) else delimiter
    special = next(
        (SPECIAL_FLAGS[f] for f in decoded_flags if f in SPECIAL_FLAGS), None
    )
    display = name.rsplit(delim, 1)[-1] if delim else name
    return {
        "canonical_name": name,
        "display_name": display,
        "delimiter": delim,
        "flags": decoded_flags,
        "special_use": special,
        "subscribed": False,
    }


def message_bodies(message: Message) -> tuple[str, str, list[dict[str, Any]]]:
    plain, html_body, attachments = "", "", []
    parts = message.walk() if message.is_multipart() else [message]
    for index, part in enumerate(parts):
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if disposition == "attachment" or filename:
            attachments.append(
                {
                    "index": index,
                    "filename": sanitize_filename(
                        decode_text(filename) or f"attachment-{index}"
                    ),
                    "content_type": part.get_content_type(),
                    "size": len(payload),
                    "content_id": part.get("Content-ID"),
                }
            )
            continue
        if part.get_content_type() in {"text/plain", "text/html"}:
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if part.get_content_type() == "text/plain" and not plain:
                plain = text
            elif part.get_content_type() == "text/html" and not html_body:
                html_body = bleach.clean(
                    text,
                    tags=bleach.sanitizer.ALLOWED_TAGS
                    | {"p", "br", "div", "span", "table", "tr", "td", "th", "img"},
                    attributes={
                        "*": ["class", "title"],
                        "a": ["href"],
                        "img": ["src", "alt"],
                    },
                    protocols={"http", "https", "cid"},
                    strip=True,
                )
    return plain, html_body, attachments


def serialize_message(
    uid: int,
    mailbox: str,
    raw: bytes,
    flags: list[str] | None = None,
    size: int | None = None,
    include_body: bool = True,
) -> dict[str, Any]:
    msg = email.message_from_bytes(raw, policy=policy.default)
    plain, html_body, attachments = message_bodies(msg)
    date = None
    try:
        date = parsedate_to_datetime(msg.get("Date", "")).isoformat()
    except Exception:
        date = msg.get("Date")
    values: dict[str, Any] = {
        "uid": uid,
        "mailbox": mailbox,
        "message_id": normalize_message_id(msg.get("Message-ID")),
        "in_reply_to": normalize_message_id(msg.get("In-Reply-To")),
        "references": parse_references(msg.get("References")),
        "sender": decode_text(msg.get("From")),
        "recipients": [a for _, a in getaddresses(msg.get_all("To", []))],
        "cc": [a for _, a in getaddresses(msg.get_all("Cc", []))],
        "bcc": [a for _, a in getaddresses(msg.get_all("Bcc", []))],
        "reply_to": decode_text(msg.get("Reply-To")),
        "subject": decode_text(msg.get("Subject")),
        "date": date,
        "size": size if size is not None else len(raw),
        "flags": flags or [],
        "seen": "\\Seen" in (flags or []),
        "flagged": "\\Flagged" in (flags or []),
        "answered": "\\Answered" in (flags or []),
        "has_attachment": bool(attachments),
        "attachment_count": len(attachments),
        "attachments": attachments,
    }
    if include_body:
        values.update({"text": plain, "html": html_body})
    return values


class MailService:
    def __init__(
        self, account: MailAccount, cipher: CredentialCipher, settings: Settings
    ):
        self.account = account
        self.cipher = cipher
        self.settings = settings

    @contextmanager
    def _imap(self) -> Iterator[IMAPClient]:
        client = IMAPClient(
            self.account.imap_host,
            self.account.imap_port,
            ssl=self.account.imap_ssl,
            timeout=self.settings.mail_timeout_seconds,
        )
        try:
            client.login(
                self.account.imap_username,
                self.cipher.decrypt(self.account.imap_password_encrypted),
            )
            yield client
        finally:
            try:
                client.logout()
            except Exception:
                pass

    async def _run(self, fn, *args):
        return await asyncio.wait_for(
            asyncio.to_thread(fn, *args), timeout=self.settings.mail_timeout_seconds + 5
        )

    def _list_mailboxes_sync(self) -> list[dict[str, Any]]:
        with self._imap() as client:
            subscribed = {name for _, _, name in client.list_sub_folders()}
            output = []
            for flags, delimiter, name in client.list_folders():
                item = mailbox_dict(flags, delimiter, name)
                item["subscribed"] = name in subscribed
                output.append(item)
            return output

    async def list_mailboxes(self) -> dict[str, Any]:
        return result(await self._run(self._list_mailboxes_sync))

    async def resolve_mailbox(self, value: str) -> str:
        return canonical_mailbox((await self.list_mailboxes())["data"], value)

    def _folder_action_sync(
        self, action: str, mailbox: str, target: str | None = None
    ) -> None:
        with self._imap() as client:
            getattr(client, action)(mailbox, target) if target else getattr(
                client, action
            )(mailbox)

    async def folder_action(
        self, action: str, mailbox: str, target: str | None = None
    ) -> dict[str, Any]:
        source = (
            mailbox
            if action == "create_folder"
            else await self.resolve_mailbox(mailbox)
        )
        if target and action == "rename_folder":
            await self._run(self._folder_action_sync, action, source, target)
        else:
            await self._run(self._folder_action_sync, action, source, None)
        return result({"mailbox": source, "target": target})

    def _search_sync(
        self,
        mailbox: str,
        criteria: list[Any],
        page: int,
        page_size: int,
        sort: str,
        descending: bool,
    ) -> list[dict[str, Any]]:
        with self._imap() as client:
            client.select_folder(mailbox, readonly=True)
            uids = list(client.search(criteria or ["ALL"]))
            rows = (
                client.fetch(uids, [b"RFC822", b"FLAGS", b"RFC822.SIZE"])
                if uids
                else {}
            )
            items = []
            for uid, fields in rows.items():
                raw = fields.get(b"RFC822", b"")
                flags = [
                    f.decode() if isinstance(f, bytes) else str(f)
                    for f in fields.get(b"FLAGS", [])
                ]
                items.append(
                    serialize_message(
                        uid,
                        mailbox,
                        raw,
                        flags,
                        fields.get(b"RFC822.SIZE"),
                        include_body=False,
                    )
                )
            key = {
                "date": lambda x: x.get("date") or "",
                "sender": lambda x: x.get("sender") or "",
                "subject": lambda x: x.get("subject") or "",
            }.get(sort, lambda x: x.get("date") or "")
            items.sort(key=key, reverse=descending)
            start = max(0, (page - 1) * page_size)
            return items[start : start + page_size]

    async def list_emails(
        self,
        mailbox: str = "INBOX",
        page: int = 1,
        page_size: int = 50,
        since: str | None = None,
        before: str | None = None,
        sender: str | None = None,
        to: str | None = None,
        cc: str | None = None,
        bcc: str | None = None,
        subject: str | None = None,
        body: str | None = None,
        text: str | None = None,
        seen: bool | None = None,
        unseen: bool | None = None,
        flagged: bool | None = None,
        unflagged: bool | None = None,
        answered: bool | None = None,
        unanswered: bool | None = None,
        draft: bool | None = None,
        deleted: bool | None = None,
        has_attachment: bool | None = None,
        min_size: int | None = None,
        max_size: int | None = None,
        message_id: str | None = None,
        in_reply_to: str | None = None,
        references: str | None = None,
        sort: str = "date",
        descending: bool = True,
    ) -> dict[str, Any]:
        canonical = await self.resolve_mailbox(mailbox)
        criteria: list[Any] = []
        for key, value in (
            ("SINCE", since),
            ("BEFORE", before),
            ("FROM", sender),
            ("TO", to),
            ("CC", cc),
            ("BCC", bcc),
            ("SUBJECT", subject),
            ("BODY", body),
            ("TEXT", text),
        ):
            if value:
                criteria.extend([key, value])
        if seen is not None:
            criteria.append("SEEN" if seen else "UNSEEN")
        if unseen is True:
            criteria.append("UNSEEN")
        if flagged is not None:
            criteria.append("FLAGGED" if flagged else "UNFLAGGED")
        if unflagged is True:
            criteria.append("UNFLAGGED")
        if answered is not None:
            criteria.append("ANSWERED" if answered else "UNANSWERED")
        if unanswered is True:
            criteria.append("UNANSWERED")
        if draft is not None:
            criteria.append("DRAFT" if draft else "UNDRAFT")
        if deleted is not None:
            criteria.append("DELETED" if deleted else "UNDELETED")
        if min_size is not None:
            criteria.extend(["LARGER", max(0, min_size)])
        if max_size is not None:
            criteria.extend(["SMALLER", max(0, max_size)])
        for header_name, value in (
            ("Message-ID", message_id),
            ("In-Reply-To", in_reply_to),
            ("References", references),
        ):
            if value:
                criteria.extend(["HEADER", header_name, value])
        data = await self._run(
            self._search_sync,
            canonical,
            criteria,
            max(page, 1),
            min(max(page_size, 1), 500),
            sort,
            descending,
        )
        if has_attachment is not None:
            data = [item for item in data if item["has_attachment"] is has_attachment]
        return result(
            data,
            warnings=[
                "IMAP SUBJECT performs a partial server-side match, not strict equality."
            ]
            if subject
            else [],
        )

    def _fetch_sync(self, mailbox: str, uid: int) -> tuple[bytes, list[str], int]:
        with self._imap() as client:
            client.select_folder(mailbox, readonly=True)
            rows = client.fetch([uid], [b"RFC822", b"FLAGS", b"RFC822.SIZE"])
            if uid not in rows:
                raise LookupError(f"UID {uid} not found in {mailbox}")
            fields = rows[uid]
            return (
                fields[b"RFC822"],
                [
                    f.decode() if isinstance(f, bytes) else str(f)
                    for f in fields.get(b"FLAGS", [])
                ],
                fields.get(b"RFC822.SIZE", 0),
            )

    async def get_email(
        self, mailbox: str, uid: int, offset: int = 0, limit: int = 1_000_000
    ) -> dict[str, Any]:
        canonical = await self.resolve_mailbox(mailbox)
        raw, flags, size = await self._run(self._fetch_sync, canonical, uid)
        data = serialize_message(uid, canonical, raw, flags, size)
        for field in ("text", "html"):
            body = data[field]
            data[field] = body[offset : offset + limit]
            data[f"{field}_truncated"] = len(body) > offset + limit
        return result(data)

    async def get_raw_message(self, mailbox: str, uid: int) -> dict[str, Any]:
        canonical = await self.resolve_mailbox(mailbox)
        raw, _, _ = await self._run(self._fetch_sync, canonical, uid)
        maximum = self.settings.max_raw_message_size_mb * 1024 * 1024
        if len(raw) > maximum:
            return failure(f"Raw message exceeds configured limit ({maximum} bytes)")
        return result(
            {
                "uid": uid,
                "mailbox": canonical,
                "encoding": "base64",
                "raw": base64.b64encode(raw).decode(),
                "size": len(raw),
            }
        )

    def _flags_sync(
        self, mailbox: str, uids: list[int], action: str, flags: list[str]
    ) -> None:
        invalid = set(flags) - SYSTEM_FLAGS
        if invalid:
            raise ValueError(f"Unsupported system flags: {sorted(invalid)}")
        with self._imap() as client:
            client.select_folder(mailbox)
            getattr(client, action)(uids, flags)

    async def change_flags(
        self, mailbox: str, uids: list[int], action: str, flags: list[str]
    ) -> dict[str, Any]:
        canonical = await self.resolve_mailbox(mailbox)
        await self._run(self._flags_sync, canonical, uids, action, flags)
        return result({"uids": uids, "mailbox": canonical, "flags": flags})

    def _move_copy_sync(
        self, source: str, target: str, uids: list[int], move: bool
    ) -> list[dict[str, Any]]:
        with self._imap() as client:
            client.select_folder(source)
            headers = client.fetch(uids, [b"BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]"])
            ids = {
                uid: normalize_message_id(
                    email.message_from_bytes(
                        fields.get(b"BODY[HEADER.FIELDS (MESSAGE-ID)]", b"")
                    ).get("Message-ID")
                )
                for uid, fields in headers.items()
            }
            if move:
                client.move(uids, target)
            else:
                client.copy(uids, target)
            client.select_folder(target, readonly=True)
            output = []
            for old_uid in uids:
                message_id = ids.get(old_uid)
                matches = (
                    list(client.search(["HEADER", "Message-ID", message_id]))
                    if message_id
                    else []
                )
                output.append(
                    {
                        "old_uid": old_uid,
                        "old_mailbox": source,
                        "new_uid": matches[-1] if matches else None,
                        "new_mailbox": target,
                        "message_id": message_id,
                    }
                )
            return output

    async def move_or_copy(
        self, mailbox: str, target: str, uids: list[int], move: bool
    ) -> dict[str, Any]:
        source = await self.resolve_mailbox(mailbox)
        destination = await self.resolve_mailbox(target)
        return result(
            await self._run(self._move_copy_sync, source, destination, uids, move)
        )

    def _permanent_delete_sync(self, mailbox: str, uids: list[int]) -> None:
        with self._imap() as client:
            client.select_folder(mailbox)
            capabilities = {
                c.decode() if isinstance(c, bytes) else str(c)
                for c in client.capabilities()
            }
            if "UIDPLUS" not in capabilities:
                raise RuntimeError(
                    "Permanent deletion requires IMAP UIDPLUS; refusing a mailbox-wide EXPUNGE"
                )
            client.delete_messages(uids)
            client.expunge(uids)

    async def permanent_delete(self, mailbox: str, uids: list[int]) -> dict[str, Any]:
        canonical = await self.resolve_mailbox(mailbox)
        await self._run(self._permanent_delete_sync, canonical, uids)
        return result({"deleted_uids": uids, "mailbox": canonical})

    def _build_message(
        self,
        to: list[str],
        subject: str,
        text_body: str | None,
        html_body: str | None,
        cc: list[str],
        bcc: list[str],
        reply_to: str | None,
        attachments: list[dict[str, str]],
        headers: dict[str, str],
    ) -> EmailMessage:
        msg = EmailMessage(policy=policy.SMTP)
        msg["Message-ID"] = make_msgid(domain=self.account.email.split("@")[-1])
        msg["Date"] = format_datetime(datetime.now(timezone.utc))
        msg["From"] = self.account.email
        msg["To"] = ", ".join(to)
        if cc:
            msg["Cc"] = ", ".join(cc)
        if bcc:
            msg["Bcc"] = ", ".join(bcc)
        if reply_to:
            msg["Reply-To"] = reply_to
        msg["Subject"] = subject
        denied = {
            "from",
            "to",
            "cc",
            "bcc",
            "subject",
            "date",
            "message-id",
            "content-type",
            "content-transfer-encoding",
        }
        for name, value in headers.items():
            if name.casefold() not in denied and re.fullmatch(r"[A-Za-z0-9-]+", name):
                msg[name] = value.replace("\r", "").replace("\n", "")
        msg.set_content(text_body or "")
        if html_body:
            msg.add_alternative(bleach.clean(html_body, strip=True), subtype="html")
        maximum = self.settings.max_attachment_size_mb * 1024 * 1024
        for item in attachments:
            raw = base64.b64decode(item["content_base64"], validate=True)
            if len(raw) > maximum:
                raise ValueError(f"Attachment exceeds {maximum} bytes")
            content_type = item.get("content_type", "application/octet-stream")
            if content_type.casefold() in {
                value.casefold() for value in self.settings.blocked_attachment_types
            }:
                raise ValueError(f"Attachment type is blocked: {content_type}")
            maintype, subtype = content_type.split("/", 1)
            msg.add_attachment(
                raw,
                maintype=maintype,
                subtype=subtype,
                filename=sanitize_filename(item.get("filename", "attachment")),
            )
        return msg

    async def send_email(
        self,
        to: list[str],
        subject: str,
        text: str | None = None,
        html_body: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        reply_to: str | None = None,
        attachments: list[dict[str, str]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        msg = self._build_message(
            to,
            subject,
            text,
            html_body,
            cc or [],
            bcc or [],
            reply_to,
            attachments or [],
            headers or {},
        )
        await asyncio.wait_for(
            aiosmtplib.send(
                msg,
                hostname=self.account.smtp_host,
                port=self.account.smtp_port,
                username=self.account.smtp_username,
                password=self.cipher.decrypt(self.account.smtp_password_encrypted),
                use_tls=self.account.smtp_ssl,
                start_tls=self.account.smtp_starttls,
                timeout=self.settings.mail_timeout_seconds,
            ),
            timeout=self.settings.mail_timeout_seconds + 5,
        )
        warnings: list[str] = []
        saved = True
        sent_folder = self.account.sent_mailbox
        try:
            if not sent_folder:
                folders = (await self.list_mailboxes())["data"]
                sent_folder = next(
                    (
                        m["canonical_name"]
                        for m in folders
                        if m["special_use"] == "sent"
                    ),
                    None,
                )
            if not sent_folder:
                raise LookupError("Sent mailbox is not configured or advertised")
            await self._run(self._append_sync, sent_folder, msg.as_bytes(), ["\\Seen"])
        except Exception:
            saved = False
            warnings.append(
                "Message sent successfully but copy could not be saved to Sent."
            )
        return result(
            {"sent": True, "saved_to_sent": saved, "message_id": msg["Message-ID"]},
            warnings=warnings,
        )

    def _append_sync(self, mailbox: str, raw: bytes, flags: list[str]) -> None:
        with self._imap() as client:
            client.append(mailbox, raw, flags=flags, msg_time=datetime.now())

    async def create_draft(
        self, to: list[str], subject: str, text: str = "", html_body: str | None = None
    ) -> dict[str, Any]:
        msg = self._build_message(to, subject, text, html_body, [], [], None, [], {})
        target = self.account.drafts_mailbox
        if not target:
            folders = (await self.list_mailboxes())["data"]
            target = next(
                (m["canonical_name"] for m in folders if m["special_use"] == "drafts"),
                None,
            )
        if not target:
            return failure("Drafts mailbox is not configured or advertised")
        await self._run(self._append_sync, target, msg.as_bytes(), ["\\Draft"])
        return result({"message_id": msg["Message-ID"], "mailbox": target})

    async def list_attachments(self, mailbox: str, uid: int) -> dict[str, Any]:
        message = (await self.get_email(mailbox, uid))["data"]
        return result(message["attachments"])

    async def download_attachment(
        self, mailbox: str, uid: int, index: int
    ) -> dict[str, Any]:
        if not self.settings.attachment_download_enabled:
            return failure("Attachment download is disabled")
        canonical = await self.resolve_mailbox(mailbox)
        raw, _, _ = await self._run(self._fetch_sync, canonical, uid)
        msg = email.message_from_bytes(raw, policy=policy.default)
        part = list(msg.walk())[index]
        payload = part.get_payload(decode=True) or b""
        maximum = self.settings.max_attachment_size_mb * 1024 * 1024
        if len(payload) > maximum:
            return failure(f"Attachment exceeds configured limit ({maximum} bytes)")
        if part.get_content_type().casefold() in {
            value.casefold() for value in self.settings.blocked_attachment_types
        }:
            return failure(f"Attachment type is blocked: {part.get_content_type()}")
        return result(
            {
                "filename": sanitize_filename(
                    decode_text(part.get_filename()) or "attachment"
                ),
                "content_type": part.get_content_type(),
                "size": len(payload),
                "encoding": "base64",
                "content": base64.b64encode(payload).decode(),
            }
        )

    async def save_attachment(
        self, mailbox: str, uid: int, index: int
    ) -> dict[str, Any]:
        downloaded = await self.download_attachment(mailbox, uid, index)
        if not downloaded["success"]:
            return downloaded
        data = downloaded["data"]
        root = self.settings.attachment_save_dir
        root.mkdir(parents=True, exist_ok=True)
        target = safe_destination(root, data["filename"])
        if target.exists():
            target = safe_destination(
                root, f"{target.stem}-{uid}-{index}{target.suffix}"
            )
        await asyncio.to_thread(target.write_bytes, base64.b64decode(data["content"]))
        return result(
            {
                "filename": target.name,
                "path": str(target),
                "size": data["size"],
                "content_type": data["content_type"],
            }
        )

    async def test_imap(self) -> dict[str, Any]:
        started = datetime.now(timezone.utc)
        mailboxes = await self.list_mailboxes()
        return result(
            {
                "imap": True,
                "mailbox_count": len(mailboxes["data"]),
                "duration_ms": int(
                    (datetime.now(timezone.utc) - started).total_seconds() * 1000
                ),
            }
        )

    async def test_smtp(self) -> dict[str, Any]:
        started = datetime.now(timezone.utc)
        client = aiosmtplib.SMTP(
            hostname=self.account.smtp_host,
            port=self.account.smtp_port,
            use_tls=self.account.smtp_ssl,
            start_tls=self.account.smtp_starttls,
            timeout=self.settings.mail_timeout_seconds,
        )
        try:
            await client.connect()
            await client.login(
                self.account.smtp_username,
                self.cipher.decrypt(self.account.smtp_password_encrypted),
            )
            return result(
                {
                    "smtp": True,
                    "duration_ms": int(
                        (datetime.now(timezone.utc) - started).total_seconds() * 1000
                    ),
                }
            )
        finally:
            if client.is_connected:
                try:
                    await client.quit()
                except Exception:
                    client.close()

    async def test(self) -> dict[str, Any]:
        imap, smtp = await asyncio.gather(
            self.test_imap(), self.test_smtp(), return_exceptions=True
        )
        errors = []
        data: dict[str, Any] = {}
        if isinstance(imap, Exception):
            errors.append(f"IMAP: {imap}")
            data["imap"] = False
        else:
            data["imap"] = imap["data"]
        if isinstance(smtp, Exception):
            errors.append(f"SMTP: {smtp}")
            data["smtp"] = False
        else:
            data["smtp"] = smtp["data"]
        return (
            partial(data, 2 - len(errors), len(errors), errors)
            if errors
            else result(data)
        )


def plain_forward(original: dict[str, Any], intro: str = "") -> str:
    header = f"\n\n---------- Forwarded message ----------\nFrom: {original['sender']}\nDate: {original['date']}\nSubject: {original['subject']}\nTo: {', '.join(original['recipients'])}\n\n"
    return intro + header + original.get("text", "")


def html_forward(original: dict[str, Any], intro: str = "") -> str:
    return f"<p>{html.escape(intro)}</p><hr><p><b>From:</b> {html.escape(original['sender'])}<br><b>Date:</b> {html.escape(str(original['date']))}<br><b>Subject:</b> {html.escape(original['subject'])}</p>{original.get('html') or '<pre>' + html.escape(original.get('text', '')) + '</pre>'}"
