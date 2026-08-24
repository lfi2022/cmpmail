"""Telegram bot dispatch logic: main menu, commands, inline-button callbacks and
the background long-polling loop. Only the chat configured via
TELEGRAM_ALLOWED_CHAT_ID is ever processed; every other chat_id is ignored
silently (no reply, no error), per the security requirement.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from app.config import Settings
from app.database import SessionLocal, check_database
from app.models import TelegramRequest
from app.security import CredentialCipher
from app.services.accounts import AccountRepository
from app.services.dolibarr import DolibarrAPIError, DolibarrService
from app.services.nextcloud import NextcloudAPIError, NextcloudService
from app.services.telegram import TelegramAPIError, TelegramService, is_allowed_chat
from app.temp_files import delete_temporary_file, resolve_temporary_file
from app.temp_files import delete_temporary_file, resolve_temporary_file

logger = logging.getLogger(__name__)

MENU_ITEMS: list[tuple[str, str]] = [
    ("Ã°Å¸â€œÂ§ Mails", "mails"),
    ("Ã°Å¸Â§Â¾ Factures", "factures"),
    ("Ã°Å¸â€™Â° Dolibarr", "dolibarr"),
    ("Ã¢ËœÂÃ¯Â¸Â Nextcloud", "nextcloud"),
    ("Ã°Å¸â€˜Â¥ Clients", "clients"),
    ("Ã°Å¸Â¤Â Partenariats", "partenariats"),
    ("Ã°Å¸â€œÂ± Facebook", "facebook"),
    ("Ã°Å¸â€“Â¥Ã¯Â¸Â Infrastructure", "infra"),
    ("Ã°Å¸â€œÅ  Rapport", "rapport"),
    ("Ã¢Å¡â„¢Ã¯Â¸Â Administration", "admin"),
]

BOT_COMMANDS: list[dict[str, str]] = [
    {"command": "start", "description": "Afficher le menu principal"},
    {"command": "menu", "description": "Afficher le menu principal"},
    {"command": "rapport", "description": "Rapport global de l'activitÃƒÂ©"},
    {"command": "mails", "description": "RÃƒÂ©sumÃƒÂ© des comptes mail"},
    {"command": "factures", "description": "Factures Dolibarr ÃƒÂ  traiter"},
    {"command": "avalider", "description": "Ãƒâ€°lÃƒÂ©ments en attente de validation"},
    {"command": "dolibarr", "description": "Ãƒâ€°tat de la connexion Dolibarr"},
    {"command": "nextcloud", "description": "Ãƒâ€°tat de la connexion Nextcloud"},
    {"command": "status", "description": "Ãƒâ€°tat de l'infrastructure"},
    {"command": "help", "description": "Afficher l'aide"},
]


def build_main_menu() -> dict[str, Any]:
    rows = [
        [{"text": MENU_ITEMS[i][0], "callback_data": f"menu:{MENU_ITEMS[i][1]}"}]
        for i in range(len(MENU_ITEMS))
    ]
    # pair items two per row for a compact menu
    paired = [rows[i][0:1] + (rows[i + 1] if i + 1 < len(rows) else []) for i in range(0, len(rows), 2)]
    return TelegramService.build_inline_keyboard(paired)


async def _section_mails(settings: Settings) -> str:
    try:
        async with SessionLocal() as db:
            repo = AccountRepository(db, CredentialCipher(settings.encryption_key))
            accounts = await repo.list()
        if not accounts:
            return "Aucun compte mail configurÃƒÂ©."
        lines = [
            f"{'Ã¢Â­Â' if a.is_default else 'Ã¢â‚¬Â¢'} {a.name} ({a.email}) Ã¢â‚¬â€ {'actif' if a.enabled else 'dÃƒÂ©sactivÃƒÂ©'}"
            for a in accounts
        ]
        return "\n".join(lines)
    except Exception as exc:
        return f"Erreur mails: {exc}"


async def _section_dolibarr(settings: Settings) -> str:
    if not (settings.dolibarr_api_url and settings.dolibarr_api_key):
        return "Dolibarr non configurÃƒÂ©."
    try:
        status = await DolibarrService(settings).status()
        return f"Dolibarr joignable. Statut: {status}"
    except DolibarrAPIError as exc:
        return f"Dolibarr injoignable: {exc}"
    except Exception as exc:
        return f"Erreur Dolibarr: {exc}"


async def _section_factures(settings: Settings) -> str:
    if not (settings.dolibarr_api_url and settings.dolibarr_api_key):
        return "Dolibarr non configurÃƒÂ©, impossible de lister les factures."
    try:
        invoices = await DolibarrService(settings).list_objects(
            "invoices", sortfield="t.tms", sortorder="DESC", limit=5
        )
        if not invoices:
            return "Aucune facture rÃƒÂ©cente."
        lines = []
        for inv in invoices if isinstance(invoices, list) else []:
            ref = inv.get("ref") if isinstance(inv, dict) else None
            total = inv.get("total_ttc") if isinstance(inv, dict) else None
            lines.append(f"{ref or '?'} Ã¢â‚¬â€ {total or '?'}")
        return "\n".join(lines) or "Aucune facture rÃƒÂ©cente."
    except DolibarrAPIError as exc:
        return f"Dolibarr injoignable: {exc}"
    except Exception as exc:
        return f"Erreur factures: {exc}"


async def _section_clients(settings: Settings) -> str:
    if not (settings.dolibarr_api_url and settings.dolibarr_api_key):
        return "Dolibarr non configurÃƒÂ©, impossible de lister les clients."
    try:
        thirdparties = await DolibarrService(settings).list_objects("thirdparties", limit=5)
        if not thirdparties:
            return "Aucun client trouvÃƒÂ©."
        names = [tp.get("name") for tp in thirdparties if isinstance(tp, dict) and tp.get("name")]
        return "\n".join(f"Ã¢â‚¬Â¢ {name}" for name in names) or "Aucun client trouvÃƒÂ©."
    except DolibarrAPIError as exc:
        return f"Dolibarr injoignable: {exc}"
    except Exception as exc:
        return f"Erreur clients: {exc}"


async def _section_nextcloud(settings: Settings) -> str:
    if not (settings.nextcloud_url and settings.nextcloud_username and settings.nextcloud_app_password):
        return "Nextcloud non configurÃƒÂ©."
    try:
        account = await NextcloudService(settings).get_account_info()
        account = account if isinstance(account, dict) else {}
        quota = account.get("quota") or {}
        used = quota.get("used") if isinstance(quota, dict) else None
        total = quota.get("total") if isinstance(quota, dict) else None
        return f"Compte {account.get('id', '?')} Ã¢â‚¬â€ quota utilisÃƒÂ©: {used or '?'}/{total or '?'}"
    except NextcloudAPIError as exc:
        return f"Nextcloud injoignable: {exc}"
    except Exception as exc:
        return f"Erreur Nextcloud: {exc}"


async def _section_facebook(settings: Settings) -> str:
    if not settings.facebook_app_id:
        return "Facebook non configurÃƒÂ©."
    default_page = settings.facebook_default_page_id or "(aucune page par dÃƒÂ©faut)"
    return f"Application configurÃƒÂ©e. Page par dÃƒÂ©faut: {default_page}"


async def _section_partenariats() -> str:
    return "Aucune source de donnÃƒÂ©es de partenariats connectÃƒÂ©e pour le moment."


async def _section_infra(settings: Settings) -> str:
    db_ok = await check_database()
    return (
        f"Base de donnÃƒÂ©es: {'OK' if db_ok else 'ERREUR'}\n"
        f"Read-only: {'oui' if settings.read_only else 'non'}\n"
        f"OpÃƒÂ©rations destructives: {'activÃƒÂ©es' if settings.destructive_operations_enabled else 'dÃƒÂ©sactivÃƒÂ©es'}"
    )


async def _section_admin(settings: Settings) -> str:
    return (
        f"OAuth activÃƒÂ©: {'oui' if settings.oauth_enabled else 'non'}\n"
        f"Authentification MCP: {'oui' if settings.mcp_auth_enabled else 'non'}\n"
        f"Rate limit: {settings.rate_limit_per_minute}/min"
    )


async def build_section(key: str, settings: Settings) -> str:
    if key == "mails":
        return await _section_mails(settings)
    if key == "factures":
        return await _section_factures(settings)
    if key == "dolibarr":
        return await _section_dolibarr(settings)
    if key == "nextcloud":
        return await _section_nextcloud(settings)
    if key == "clients":
        return await _section_clients(settings)
    if key == "partenariats":
        return await _section_partenariats()
    if key == "facebook":
        return await _section_facebook(settings)
    if key == "infra":
        return await _section_infra(settings)
    if key == "admin":
        return await _section_admin(settings)
    if key == "rapport":
        parts = []
        for label, section_key in MENU_ITEMS:
            if section_key == "rapport":
                continue
            text = await build_section(section_key, settings)
            parts.append(f"<b>{label}</b>\n{text}")
        return "\n\n".join(parts)
    return "Section inconnue."


def _menu_label(key: str) -> str:
    for label, section_key in MENU_ITEMS:
        if section_key == key:
            return label
    return key


async def create_button_request(
    text: str,
    options: list[dict[str, str]],
    *,
    kind: str = "generic",
    context: dict[str, Any] | None = None,
) -> tuple[str, list[list[dict[str, str]]]]:
    """Persist a pending question and build its inline keyboard. Returns (request_id, rows)."""
    request_id = secrets.token_hex(6)
    rows = [[{"text": opt["label"], "callback_data": f"cb:{request_id}:{opt['value']}"}] for opt in options]
    async with SessionLocal() as db:
        db.add(
            TelegramRequest(
                id=request_id,
                kind=kind,
                text=text,
                options=options,
                context=context or {},
                chat_id="",
                status="pending",
            )
        )
        await db.commit()
    return request_id, rows


async def mark_request_delivered(request_id: str, chat_id: str, message_id: int | None) -> None:
    async with SessionLocal() as db:
        request = await db.get(TelegramRequest, request_id)
        if request is not None:
            request.chat_id = chat_id
            request.message_id = message_id
            await db.commit()


async def get_request(request_id: str) -> TelegramRequest | None:
    async with SessionLocal() as db:
        return await db.get(TelegramRequest, request_id)


async def _handle_menu_callback(service: TelegramService, chat_id: str, message_id: int, key: str) -> None:
    text = await build_section(key, service.settings)
    label = _menu_label(key)
    back_row = [[{"text": "Ã¢Â¬â€¦Ã¯Â¸Â Menu", "callback_data": "menu:home"}]]
    if key == "home":
        await service.edit_message_text(chat_id, message_id, "Menu principal :", reply_markup=build_main_menu())
        return
    await service.edit_message_text(
        chat_id,
        message_id,
        f"<b>{label}</b>\n\n{text}",
        reply_markup=TelegramService.build_inline_keyboard(back_row),
    )


async def _process_invoice_action(settings: Settings, context: dict[str, Any], value: str) -> str:
    """Execute only the explicitly selected invoice hand-off action."""
    if value == "VALIDATE":
        return "Invoice marked as validated."
    if value == "REVIEW":
        return "Invoice kept for review."
    if value == "REJECT":
        return "Invoice marked as rejected; no file was transferred."
    temporary_file_id = str(context.get("temporary_file_id") or "")
    path, metadata = resolve_temporary_file(settings, temporary_file_id)
    if value == "NEXTCLOUD":
        destination = str(context.get("nextcloud_destination_path") or "")
        if not destination:
            raise ValueError("No Nextcloud destination was configured for this request")
        uploaded = await NextcloudService(settings).upload_temporary_file(path, destination, create_missing_folders=True, overwrite=False)
        outcome = f"Uploaded to Nextcloud: {uploaded.get('path', destination)}"
    elif value == "DOLIBARR":
        object_id = str(context.get("dolibarr_supplier_invoice_id") or "")
        if not object_id:
            raise ValueError("No Dolibarr supplier invoice was configured for this request")
        await DolibarrService(settings).attach_file("supplierinvoices", object_id, path.read_bytes(), metadata["filename"], modulepart="supplier_invoice")
        outcome = f"Attached to Dolibarr supplier invoice {object_id}."
    else:
        raise ValueError("Unsupported invoice action")
    if context.get("consume"):
        delete_temporary_file(settings, temporary_file_id)
        outcome += " Temporary file deleted."
    return outcome

async def _process_invoice_action(settings: Settings, context: dict[str, Any], value: str) -> str:
    if value == "VALIDATE": return "Invoice marked as validated."
    if value == "REVIEW": return "Invoice kept for review."
    if value == "REJECT": return "Invoice marked as rejected; no file was transferred."
    temporary_file_id = str(context.get("temporary_file_id") or "")
    path, metadata = resolve_temporary_file(settings, temporary_file_id)
    if value == "NEXTCLOUD":
        destination = str(context.get("nextcloud_destination_path") or "")
        if not destination: raise ValueError("No Nextcloud destination was configured")
        uploaded = await NextcloudService(settings).upload_temporary_file(path, destination, create_missing_folders=True, overwrite=False)
        outcome = f"Uploaded to Nextcloud: {uploaded.get('path', destination)}"
    elif value == "DOLIBARR":
        object_id = str(context.get("dolibarr_supplier_invoice_id") or "")
        if not object_id: raise ValueError("No Dolibarr supplier invoice was configured")
        await DolibarrService(settings).attach_file("supplierinvoices", object_id, path.read_bytes(), metadata["filename"], modulepart="supplier_invoice")
        outcome = f"Attached to Dolibarr supplier invoice {object_id}."
    else: raise ValueError("Unsupported invoice action")
    if context.get("consume"):
        delete_temporary_file(settings, temporary_file_id)
        outcome += " Temporary file deleted."
    return outcome


async def _handle_button_answer_callback(service: TelegramService, callback_query_id: str, chat_id: str, message_id: int, request_id: str, value: str) -> None:
    async with SessionLocal() as db:
        request = await db.get(TelegramRequest, request_id)
        if request is None:
            await service.answer_callback_query(callback_query_id, text="Request not found or expired.", show_alert=True); return
        if request.status != "pending":
            await service.answer_callback_query(callback_query_id, text="Already processed.", show_alert=True); return
        chosen_label = next((opt.get("label", value) for opt in request.options if opt.get("value") == value), value)
        request.status = "processing" if request.kind == "invoice_validation" else "answered"
        request.answer = value
        request.answered_at = datetime.now(timezone.utc)
        context = dict(request.context or {})
        await db.commit()
    await service.answer_callback_query(callback_query_id, text="Processing..." if request.kind == "invoice_validation" else f"Choice saved: {chosen_label}")
    outcome = f"Choice: {chosen_label}"
    if request.kind == "invoice_validation":
        try:
            outcome = await _process_invoice_action(service.settings, context, value)
            async with SessionLocal() as db:
                stored = await db.get(TelegramRequest, request_id)
                if stored is not None:
                    stored.status = "completed"; stored.context = {**context, "outcome": outcome}; await db.commit()
        except Exception as exc:
            outcome = f"Action failed: {exc.__class__.__name__}"
            async with SessionLocal() as db:
                stored = await db.get(TelegramRequest, request_id)
                if stored is not None:
                    stored.status = "failed"; stored.context = {**context, "last_error": exc.__class__.__name__}; await db.commit()
    try: await service.edit_message_text(chat_id, message_id, f"{request.text}\n\nResult: {outcome}")
    except TelegramAPIError: pass


async def handle_update(settings: Settings, update: dict[str, Any]) -> None:
    service = TelegramService(settings)
    callback = update.get("callback_query")
    message = update.get("message")

    if callback:
        chat_id = str(((callback.get("message") or {}).get("chat") or {}).get("id", ""))
        if not is_allowed_chat(chat_id, settings.telegram_allowed_chat_id):
            logger.warning("Ignoring Telegram callback from unauthorized chat_id=%s", chat_id)
            return
        message_id = (callback.get("message") or {}).get("message_id")
        data = str(callback.get("data") or "")
        callback_query_id = callback.get("id")
        try:
            if data.startswith("menu:"):
                await _handle_menu_callback(service, chat_id, message_id, data.split(":", 1)[1])
                await service.answer_callback_query(callback_query_id)
            elif data.startswith("cb:"):
                _, request_id, value = data.split(":", 2)
                await _handle_button_answer_callback(service, callback_query_id, chat_id, message_id, request_id, value)
            else:
                await service.answer_callback_query(callback_query_id)
        except Exception:
            logger.exception("Error handling Telegram callback")
            try:
                await service.answer_callback_query(callback_query_id, text="Erreur interne.", show_alert=True)
            except Exception:
                pass
        return

    if message and "text" in message:
        chat_id = str((message.get("chat") or {}).get("id", ""))
        if not is_allowed_chat(chat_id, settings.telegram_allowed_chat_id):
            logger.warning("Ignoring Telegram message from unauthorized chat_id=%s", chat_id)
            return
        text = str(message.get("text") or "").strip()
        command = text.split()[0].split("@")[0].lower() if text.startswith("/") else ""
        try:
            if command in {"/start", "/menu"}:
                await service.send_message("Menu principal :", reply_markup=build_main_menu())
            elif command == "/help":
                help_text = "\n".join(f"/{c['command']} Ã¢â‚¬â€ {c['description']}" for c in BOT_COMMANDS)
                await service.send_message(help_text)
            elif command == "/rapport":
                await service.send_report("Rapport global", (await build_section("rapport", settings)).split("\n"))
            elif command in {"/mails", "/factures", "/dolibarr", "/nextcloud", "/status"}:
                key = {"mails": "mails", "factures": "factures", "dolibarr": "dolibarr", "nextcloud": "nextcloud", "status": "infra"}[
                    command[1:]
                ]
                await service.send_report(_menu_label(key) if key != "infra" else "Infrastructure", (await build_section(key, settings)).split("\n"))
            elif command == "/avalider":
                pending = await _list_pending_requests()
                if not pending:
                    await service.send_message("Aucun ÃƒÂ©lÃƒÂ©ment en attente de validation.")
                else:
                    lines = [f"{p.id}: {p.text}" for p in pending]
                    await service.send_report("En attente de validation", lines)
            elif text.startswith("/"):
                await service.send_message("Commande inconnue. Tapez /help pour la liste des commandes.")
            else:
                await service.send_message("Utilisez /menu pour afficher les options disponibles.")
        except TelegramAPIError:
            logger.exception("Error replying to Telegram command")


async def _list_pending_requests() -> list[TelegramRequest]:
    async with SessionLocal() as db:
        rows = await db.scalars(
            select(TelegramRequest).where(TelegramRequest.status == "pending").order_by(TelegramRequest.created_at.desc()).limit(10)
        )
        return list(rows.all())


async def run_telegram_poller(settings: Settings, stop_event: asyncio.Event) -> None:
    """Long-poll Telegram getUpdates and dispatch updates until stop_event is set."""
    service = TelegramService(settings)
    try:
        await service.delete_webhook()
    except Exception:
        logger.warning("Could not clear Telegram webhook before polling")
    offset: int | None = None
    while not stop_event.is_set():
        try:
            updates = await service.get_updates(
                offset=offset,
                timeout=settings.telegram_poll_timeout_seconds,
                allowed_updates=["message", "callback_query"],
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Telegram poller error; backing off")
            await asyncio.sleep(5)
            continue
        for update in updates or []:
            offset = update.get("update_id", 0) + 1
            try:
                await handle_update(settings, update)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Unhandled error processing Telegram update")
