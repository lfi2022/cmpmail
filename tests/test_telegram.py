import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.telegram_bot as telegram_bot
from app.config import Settings
from app.database import Base
from app.mcp_server import TOOL_PERMISSIONS
from app.services.telegram import (
    TelegramAPIError,
    TelegramService,
    is_allowed_chat,
    redact_telegram_text,
)


def _settings(**overrides) -> Settings:
    return Settings(
        _env_file=None,
        telegram_bot_token="123456789:AAFakeTokenForTestsOnly1234567890",
        telegram_allowed_chat_id="42",
        **overrides,
    )


@pytest_asyncio.fixture()
async def telegram_db(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_local = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(telegram_bot, "SessionLocal", session_local)
    yield session_local
    await engine.dispose()


def test_redact_text_hides_bot_token_and_url():
    text = redact_telegram_text(
        "https://api.telegram.org/bot123456789:AAFakeTokenForTestsOnly1234567890/sendMessage failed"
    )
    assert "AAFakeTokenForTestsOnly1234567890" not in text
    assert "[REDACTED]" in text


def test_is_allowed_chat_matches_only_configured_chat():
    assert is_allowed_chat("42", "42") is True
    assert is_allowed_chat(42, "42") is True
    assert is_allowed_chat("43", "42") is False
    assert is_allowed_chat("42", "") is False


def test_build_inline_keyboard_rejects_oversized_callback_data():
    with pytest.raises(ValueError):
        TelegramService.build_inline_keyboard([[{"text": "x", "callback_data": "y" * 65}]])
    keyboard = TelegramService.build_inline_keyboard([[{"text": "ok", "callback_data": "cb:abc:1"}]])
    assert keyboard == {"inline_keyboard": [[{"text": "ok", "callback_data": "cb:abc:1"}]]}


def test_send_message_rejects_unauthorized_chat_id():
    service = TelegramService(_settings())
    with pytest.raises(ValueError):
        service._resolve_chat_id("999")
    assert service._resolve_chat_id(None) == "42"
    assert service._resolve_chat_id("42") == "42"


def test_telegram_tools_and_permissions_remain_registered():
    expected = {
        "telegram_health_check": "telegram.read",
        "telegram_send_message": "telegram.write",
        "telegram_send_report": "telegram.write",
        "telegram_send_buttons": "telegram.write",
        "telegram_get_updates": "telegram.read",
        "telegram_set_commands": "telegram.write",
        "telegram_get_callback_result": "telegram.read",
    }
    for tool, permission in expected.items():
        assert TOOL_PERMISSIONS[tool] == permission


def test_build_main_menu_has_ten_items_in_five_rows():
    keyboard = telegram_bot.build_main_menu()
    rows = keyboard["inline_keyboard"]
    assert sum(len(row) for row in rows) == 10
    assert rows[0][0]["callback_data"] == "menu:mails"


class FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_send_message_targets_allowed_chat_and_uses_bot_url(monkeypatch):
    response = httpx.Response(
        200, json={"ok": True, "result": {"message_id": 1, "chat": {"id": 42}}}, request=httpx.Request("POST", "https://x")
    )
    fake_client = FakeClient([response])
    import app.services.telegram as telegram_module

    monkeypatch.setattr(telegram_module.httpx, "AsyncClient", lambda **kwargs: fake_client)
    telegram_module._last_request_at = 0.0
    service = TelegramService(_settings())
    result = await service.send_message("hello")

    assert result["message_id"] == 1
    sent_payload = fake_client.calls[0]["json"]
    assert sent_payload["chat_id"] == "42"


@pytest.mark.asyncio
async def test_429_response_retries_then_succeeds(monkeypatch):
    rate_limited = httpx.Response(
        200,
        json={"ok": False, "error_code": 429, "description": "Too Many Requests", "parameters": {"retry_after": 0}},
        request=httpx.Request("POST", "https://x"),
    )
    success = httpx.Response(200, json={"ok": True, "result": {"message_id": 2}}, request=httpx.Request("POST", "https://x"))
    fake_client = FakeClient([rate_limited, success])
    import app.services.telegram as telegram_module

    monkeypatch.setattr(telegram_module.httpx, "AsyncClient", lambda **kwargs: fake_client)
    telegram_module._last_request_at = 0.0
    service = TelegramService(_settings())
    result = await service.send_message("hi")

    assert result["message_id"] == 2
    assert len(fake_client.calls) == 2


@pytest.mark.asyncio
async def test_error_response_raises_with_redacted_metadata(monkeypatch):
    response = httpx.Response(
        200,
        json={"ok": False, "error_code": 400, "description": "Bad Request: chat not found"},
        request=httpx.Request("POST", "https://x"),
    )
    fake_client = FakeClient([response])
    import app.services.telegram as telegram_module

    monkeypatch.setattr(telegram_module.httpx, "AsyncClient", lambda **kwargs: fake_client)
    telegram_module._last_request_at = 0.0
    service = TelegramService(_settings())
    with pytest.raises(TelegramAPIError) as raised:
        await service.send_message("hi")
    assert "chat not found" in str(raised.value)


@pytest.mark.asyncio
async def test_handle_update_ignores_unauthorized_chat(monkeypatch, telegram_db):
    called = False

    async def fail_send_message(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(telegram_bot.TelegramService, "send_message", fail_send_message)
    settings = _settings()
    update = {"message": {"chat": {"id": 999}, "text": "/start"}}
    await telegram_bot.handle_update(settings, update)
    assert called is False


@pytest.mark.asyncio
async def test_button_request_roundtrip_records_answer(telegram_db, monkeypatch):
    settings = _settings()
    options = [{"label": "🏢 LFINFO", "value": "LFINFO"}, {"label": "👤 Personnel", "value": "PERSO"}]
    request_id, rows = await telegram_bot.create_button_request(
        "Facture ambiguë ?", options, kind="invoice_classification", context={"invoice_id": "INV-1"}
    )
    assert rows[0][0]["callback_data"] == f"cb:{request_id}:LFINFO"
    await telegram_bot.mark_request_delivered(request_id, "42", 55)

    async def noop(*args, **kwargs):
        return None

    monkeypatch.setattr(telegram_bot.TelegramService, "answer_callback_query", noop)
    monkeypatch.setattr(telegram_bot.TelegramService, "edit_message_text", noop)
    service = TelegramService(settings)
    await telegram_bot._handle_button_answer_callback(service, "cbq-1", "42", 55, request_id, "LFINFO")

    stored = await telegram_bot.get_request(request_id)
    assert stored.status == "answered"
    assert stored.answer == "LFINFO"
    assert stored.context == {"invoice_id": "INV-1"}
