"""Minimal client for the Telegram Bot API, restricted to a single allowed chat.

Reference: https://core.telegram.org/bots/api

Only HTTPS calls to https://api.telegram.org/bot<token>/<method> are made. The
bot token never appears in logs, exceptions or tool responses: every error
path is passed through `redact_telegram_text` first. All outbound messages
target the single chat configured via TELEGRAM_ALLOWED_CHAT_ID; inbound
updates from any other chat are the caller's responsibility to ignore (see
`is_allowed_chat`).
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)

_TOKEN_PATTERN = re.compile(r"\d{6,12}:[A-Za-z0-9_-]{20,}")
_BOT_URL_PATTERN = re.compile(r"/bot[^/\s]+/")

# Telegram has no hard documented per-chat limit, but ~1 message/second to the
# same chat is the commonly recommended ceiling; throttle process-wide.
_MIN_INTERVAL_SECONDS = 0.35
_rate_lock = asyncio.Lock()
_last_request_at = 0.0


def redact_telegram_text(value: object) -> str:
    """Strip the bot token from URLs and free text before logging or returning it."""
    text = str(value)
    text = _BOT_URL_PATTERN.sub("/bot[REDACTED]/", text)
    return _TOKEN_PATTERN.sub("[REDACTED]", text)


def is_allowed_chat(chat_id: object, allowed_chat_id: str) -> bool:
    allowed = str(allowed_chat_id or "").strip()
    return bool(allowed) and str(chat_id) == allowed


class TelegramAPIError(RuntimeError):
    def __init__(self, message: str, *, error_code: int | None = None, metadata: dict[str, Any] | None = None):
        super().__init__(message)
        self.error_code = error_code
        self.metadata = metadata or {}


class TelegramService:
    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def _token(self) -> str:
        token = (self.settings.telegram_bot_token or "").strip()
        if not token:
            raise ValueError("TELEGRAM_BOT_TOKEN is not configured")
        return token

    @property
    def allowed_chat_id(self) -> str:
        chat_id = str(self.settings.telegram_allowed_chat_id or "").strip()
        if not chat_id:
            raise ValueError("TELEGRAM_ALLOWED_CHAT_ID is not configured")
        return chat_id

    def _resolve_chat_id(self, chat_id: str | int | None) -> str:
        if chat_id is None:
            return self.allowed_chat_id
        if not is_allowed_chat(chat_id, self.allowed_chat_id):
            raise ValueError("chat_id is not the configured allowed chat")
        return str(chat_id)

    async def _request(self, method: str, *, params: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        global _last_request_at
        url = f"https://api.telegram.org/bot{self._token}/{method}"
        request_timeout = httpx.Timeout(timeout or self.settings.telegram_timeout_seconds, connect=10.0)
        payload = {k: v for k, v in (params or {}).items() if v is not None}
        async with _rate_lock:
            wait = _MIN_INTERVAL_SECONDS - (time.monotonic() - _last_request_at)
            if wait > 0:
                await asyncio.sleep(wait)
            _last_request_at = time.monotonic()
        for attempt in range(2):
            try:
                async with httpx.AsyncClient(timeout=request_timeout) as client:
                    response = await client.post(url, json=payload)
            except httpx.RequestError as exc:
                logger.warning("Telegram network error method=%s error=%s", method, exc.__class__.__name__)
                raise TelegramAPIError(
                    f"Telegram request failed on {method}: {exc.__class__.__name__}"
                ) from exc
            try:
                data = response.json()
            except ValueError:
                data = {}
            if data.get("ok"):
                return data.get("result")
            error_code = data.get("error_code")
            description = str(data.get("description") or "Telegram API error")
            if error_code == 429 and attempt == 0:
                retry_after = min(float((data.get("parameters") or {}).get("retry_after", 1)), 10.0)
                logger.warning("Telegram rate limited method=%s retry_after=%s", method, retry_after)
                await asyncio.sleep(retry_after)
                continue
            logger.warning("Telegram API error method=%s code=%s", method, error_code)
            raise TelegramAPIError(
                f"Telegram API error on {method}: {redact_telegram_text(description)}",
                error_code=error_code,
                metadata={"description": redact_telegram_text(description)},
            )
        raise TelegramAPIError(f"Telegram API error on {method}: rate limited")

    async def get_me(self) -> Any:
        return await self._request("getMe")

    async def send_message(
        self,
        text: str,
        *,
        chat_id: str | int | None = None,
        reply_markup: dict[str, Any] | None = None,
        parse_mode: str = "HTML",
    ) -> Any:
        if not text or not text.strip():
            raise ValueError("text is required")
        params: dict[str, Any] = {
            "chat_id": self._resolve_chat_id(chat_id),
            "text": text[:4096],
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }
        if reply_markup is not None:
            params["reply_markup"] = reply_markup
        return await self._request("sendMessage", params=params)

    async def send_report(self, title: str, lines: list[str], *, chat_id: str | int | None = None) -> Any:
        body = "\n".join(f"• {line}" for line in lines) if lines else "(aucune donnée)"
        text = f"<b>{title}</b>\n\n{body}"
        return await self.send_message(text, chat_id=chat_id)

    @staticmethod
    def build_inline_keyboard(rows: list[list[dict[str, str]]]) -> dict[str, Any]:
        for row in rows:
            for button in row:
                if len(str(button.get("callback_data", "")).encode()) > 64:
                    raise ValueError("callback_data exceeds Telegram's 64-byte limit")
        return {"inline_keyboard": rows}

    async def send_buttons(
        self,
        text: str,
        rows: list[list[dict[str, str]]],
        *,
        chat_id: str | int | None = None,
        parse_mode: str = "HTML",
    ) -> Any:
        keyboard = self.build_inline_keyboard(rows)
        return await self.send_message(text, chat_id=chat_id, reply_markup=keyboard, parse_mode=parse_mode)

    async def edit_message_text(
        self,
        chat_id: str | int,
        message_id: int,
        text: str,
        *,
        reply_markup: dict[str, Any] | None = None,
        parse_mode: str = "HTML",
    ) -> Any:
        params: dict[str, Any] = {
            "chat_id": self._resolve_chat_id(chat_id),
            "message_id": message_id,
            "text": text[:4096],
            "parse_mode": parse_mode,
        }
        if reply_markup is not None:
            params["reply_markup"] = reply_markup
        return await self._request("editMessageText", params=params)

    async def answer_callback_query(
        self, callback_query_id: str, *, text: str | None = None, show_alert: bool = False
    ) -> Any:
        params = {"callback_query_id": callback_query_id, "text": text, "show_alert": show_alert}
        return await self._request("answerCallbackQuery", params=params)

    async def get_updates(
        self,
        *,
        offset: int | None = None,
        limit: int = 100,
        timeout: int = 0,
        allowed_updates: list[str] | None = None,
    ) -> Any:
        params: dict[str, Any] = {"limit": max(1, min(int(limit), 100)), "timeout": max(0, int(timeout))}
        if offset is not None:
            params["offset"] = offset
        if allowed_updates is not None:
            params["allowed_updates"] = allowed_updates
        return await self._request("getUpdates", params=params, timeout=timeout + 10)

    async def delete_webhook(self) -> Any:
        return await self._request("deleteWebhook", params={"drop_pending_updates": False})

    async def set_my_commands(self, commands: list[dict[str, str]]) -> Any:
        return await self._request("setMyCommands", params={"commands": commands})
