import pytest

from app.config import Settings
from app.mcp_server import TOOL_PERMISSIONS
from app.services.dolibarr import DolibarrService
from app.services.nextcloud import NextcloudService
from app.temp_files import store_temporary_file


def test_new_transfer_tools_have_explicit_permissions():
    assert TOOL_PERMISSIONS["mail_get_attachment"] == "mail.attachments"
    assert TOOL_PERMISSIONS["nextcloud_upload_temporary_file"] == "nextcloud.write"
    assert TOOL_PERMISSIONS["dolibarr_attach_temporary_file"] == "dolibarr.write"


@pytest.mark.asyncio
async def test_nextcloud_upload_uses_server_side_temporary_content(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, temporary_file_dir=tmp_path, nextcloud_url="https://cloud.example", nextcloud_username="alice", nextcloud_app_password="secret")
    stored = store_temporary_file(settings, b"pdf", "invoice.pdf", "application/pdf")
    from app.temp_files import resolve_temporary_file
    path, _ = resolve_temporary_file(settings, stored["temporary_file_id"])
    service = NextcloudService(settings)
    calls = {}
    async def ensure(path): calls["folder"] = path
    async def upload(path, content, overwrite=False):
        calls.update(path=path, content=content, overwrite=overwrite)
        return {"path": path}
    monkeypatch.setattr(service, "ensure_folder", ensure)
    monkeypatch.setattr(service, "upload_file", upload)
    out = await service.upload_temporary_file(path, "Invoices/2026/invoice.pdf", overwrite=False)
    assert out["path"] == "Invoices/2026/invoice.pdf"
    assert calls == {"folder": "Invoices/2026", "path": "Invoices/2026/invoice.pdf", "content": b"pdf", "overwrite": False}


@pytest.mark.asyncio
async def test_dolibarr_attachment_encodes_only_inside_server_call(monkeypatch):
    settings = Settings(_env_file=None, dolibarr_api_url="https://erp.example/api", dolibarr_api_key="secret")
    service = DolibarrService(settings)
    captured = {}
    async def get_object(resource, object_id): return {"ref": "FA-2026-001"}
    async def request(method, path, **kwargs):
        captured.update(method=method, path=path, **kwargs)
        return {"ok": True}
    monkeypatch.setattr(service, "get_object", get_object)
    monkeypatch.setattr(service, "_request", request)
    assert await service.attach_file("supplierinvoices", "12", b"pdf", "invoice.pdf") == {"ok": True}
    assert captured["path"] == "documents/upload"
    assert captured["json_body"]["modulepart"] == "supplier_invoice"
    assert captured["json_body"]["ref"] == "FA-2026-001"
    assert captured["json_body"]["filecontent"] == "cGRm"
