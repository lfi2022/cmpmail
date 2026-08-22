from app.services.facebook import (
    PAGE_FIELDS,
    redact_facebook_data,
    redact_facebook_text,
    validate_facebook_id,
    validate_image_url,
)
from app.mcp_server import TOOL_PERMISSIONS


def test_page_fields_never_include_created_time():
    assert "created_time" not in PAGE_FIELDS
    assert {"id", "name", "picture{url}"}.issubset(PAGE_FIELDS)


def test_redaction_removes_tokens_and_tokenized_paging_urls():
    payload = {
        "data": [{"id": "104823885473411", "access_token": "EAAsecret"}],
        "paging": {"next": "https://graph.facebook.com/?access_token=EAAsecret"},
        "nested": {"client_secret": "secret", "name": "safe"},
    }
    assert redact_facebook_data(payload) == {
        "data": [{"id": "104823885473411"}],
        "paging": {},
        "nested": {"name": "safe"},
    }


def test_error_text_redacts_graph_token_fragments():
    error = redact_facebook_text("access_token=EAAsecret&foo=bar EAAanother")
    assert "EAAsecret" not in error
    assert "EAAanother" not in error
    assert "[REDACTED]" in error


def test_facebook_ids_stay_strings_and_are_validated():
    assert validate_facebook_id("104823885473411", page=True) == "104823885473411"
    assert validate_facebook_id("104823885473411_123456") == "104823885473411_123456"
    for invalid in ("", "123a", "1_2_3", "-1"):
        try:
            validate_facebook_id(invalid)
        except ValueError:
            continue
        raise AssertionError(f"Expected {invalid!r} to be rejected")


def test_image_urls_require_http_or_https():
    assert validate_image_url("https://example.com/image.jpg") == "https://example.com/image.jpg"
    for invalid in ("file:///tmp/a.jpg", "javascript:alert(1)", "relative.jpg"):
        try:
            validate_image_url(invalid)
        except ValueError:
            continue
        raise AssertionError(f"Expected {invalid!r} to be rejected")


def test_facebook_tools_and_permissions_remain_registered():
    expected = {
        "facebook_list_pages",
        "facebook_get_page",
        "facebook_list_posts",
        "facebook_get_post",
        "facebook_create_post",
        "facebook_create_photo_post",
        "facebook_delete_post",
        "facebook_get_comments",
        "facebook_reply_comment",
        "facebook_hide_comment",
        "facebook_get_insights",
        "facebook_health_check",
    }
    assert expected.issubset(TOOL_PERMISSIONS)
