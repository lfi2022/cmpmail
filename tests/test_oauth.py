import asyncio
import base64
import hashlib
import re
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import Settings
from app.database import Base, get_db
from app.auth import limiter
from app.models import OAuthUser
from app.oauth import DEFAULT_SCOPES, router
from app.security import hash_secret


@pytest.fixture()
def oauth_app(tmp_path):
    limiter.buckets.clear()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    settings = Settings(
        _env_file=None,
        public_url="https://mcp.example",
        oauth_issuer="https://mcp.example",
        oauth_resource="https://mcp.example/mcp",
        oauth_signing_key_path=private,
        oauth_signing_public_key_path=public,
        secret_key="test-secret-at-least-32-bytes-long",
        secure_cookies=False,
    )
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'oauth.db'}")
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as db:
            db.add(
                OAuthUser(
                    username="admin",
                    email="admin@example.com",
                    password_hash=hash_secret("correct horse battery staple"),
                )
            )
            await db.commit()

    asyncio.run(setup())
    app = FastAPI()
    app.include_router(router)

    async def override_db():
        async with sessions() as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    from app.config import get_settings

    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app) as client:
        yield client, settings
    asyncio.run(engine.dispose())


def register(client, redirect="https://chatgpt.com/aip/callback", scope=None):
    return client.post(
        "/oauth/register",
        json={
            "client_name": "ChatGPT",
            "redirect_uris": [redirect],
            "token_endpoint_auth_method": "none",
            "scope": scope or " ".join(DEFAULT_SCOPES),
        },
    )


def verifier_pair():
    verifier = "v" * 64
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def params(client_id, redirect="https://chatgpt.com/aip/callback", scope=None, **extra):
    _, challenge = verifier_pair()
    return {
        "client_id": client_id,
        "redirect_uri": redirect,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": "https://mcp.example/mcp",
        "scope": scope or " ".join(DEFAULT_SCOPES),
        "state": "opaque-state",
        **extra,
    }


def hidden(page, name):
    return re.search(rf"name={name} value='([^']+)'", page.text).group(1)


def authorize_code(client, client_id, scope=None):
    response = client.get("/oauth/authorize", params=params(client_id, scope=scope))
    login = client.post(
        "/oauth/login",
        data={
            "username": "admin",
            "password": "correct horse battery staple",
            "request_token": hidden(response, "request_token"),
            "csrf": hidden(response, "csrf"),
        },
    )
    consent = login
    response = client.post(
        "/oauth/authorize",
        data={
            "decision": "allow",
            "request_token": hidden(consent, "request_token"),
            "csrf": hidden(consent, "csrf"),
        },
        follow_redirects=False,
    )
    return parse_qs(urlparse(response.headers["location"]).query)["code"][0]


def exchange(client, client_id, code, verifier=None):
    value, _ = verifier_pair()
    return client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": "https://chatgpt.com/aip/callback",
            "code_verifier": verifier or value,
            "resource": "https://mcp.example/mcp",
        },
    )


def test_01_oauth_discovery(oauth_app):
    client, _ = oauth_app
    body = client.get("/.well-known/oauth-authorization-server").json()
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["authorization_response_iss_parameter_supported"] is True


def test_02_oidc_discovery(oauth_app):
    client, _ = oauth_app
    assert client.get("/.well-known/openid-configuration").json()[
        "id_token_signing_alg_values_supported"
    ] == ["RS256"]


def test_03_protected_resource_metadata(oauth_app):
    client, _ = oauth_app
    assert (
        client.get("/.well-known/oauth-protected-resource").json()["resource"]
        == "https://mcp.example/mcp"
    )


def test_04_jwks_contains_public_rsa_only(oauth_app):
    client, _ = oauth_app
    key = client.get("/.well-known/jwks.json").json()["keys"][0]
    assert key["kty"] == "RSA" and key["alg"] == "RS256" and "d" not in key


def test_05_dynamic_public_client_registration(oauth_app):
    client, _ = oauth_app
    response = register(client)
    assert (
        response.status_code == 201
        and response.json()["token_endpoint_auth_method"] == "none"
    )


def test_06_dcr_rejects_insecure_remote_redirect(oauth_app):
    client, _ = oauth_app
    assert register(client, "http://evil.example/callback").status_code == 400


def test_07_dcr_rejects_fragment_and_wildcard(oauth_app):
    client, _ = oauth_app
    assert register(client, "https://example.com/*#token").status_code == 400


def test_08_authorize_requires_all_parameters(oauth_app):
    client, _ = oauth_app
    assert client.get("/oauth/authorize").status_code == 400


def test_09_redirect_uri_requires_exact_match(oauth_app):
    client, _ = oauth_app
    client_id = register(client).json()["client_id"]
    assert (
        client.get(
            "/oauth/authorize",
            params=params(client_id, redirect="https://chatgpt.com/other"),
        ).status_code
        == 400
    )


def test_10_pkce_s256_is_mandatory(oauth_app):
    client, _ = oauth_app
    client_id = register(client).json()["client_id"]
    query = params(client_id, code_challenge_method="plain")
    response = client.get("/oauth/authorize", params=query, follow_redirects=False)
    assert "error=invalid_request" in response.headers["location"]


def test_11_resource_must_match(oauth_app):
    client, _ = oauth_app
    client_id = register(client).json()["client_id"]
    response = client.get(
        "/oauth/authorize",
        params=params(client_id, resource="https://evil.example/mcp"),
        follow_redirects=False,
    )
    assert "error=invalid_target" in response.headers["location"]


def test_12_unknown_scope_is_rejected(oauth_app):
    client, _ = oauth_app
    assert register(client, scope="mail.read root").status_code == 400


def test_13_bad_login_is_rejected(oauth_app):
    client, _ = oauth_app
    client_id = register(client).json()["client_id"]
    page = client.get("/oauth/authorize", params=params(client_id))
    response = client.post(
        "/oauth/login",
        data={
            "username": "admin",
            "password": "wrong",
            "request_token": hidden(page, "request_token"),
            "csrf": hidden(page, "csrf"),
        },
    )
    assert response.status_code == 401


def test_14_consent_denial_preserves_state_and_issuer(oauth_app):
    client, _ = oauth_app
    client_id = register(client).json()["client_id"]
    page = client.get("/oauth/authorize", params=params(client_id))
    consent = client.post(
        "/oauth/login",
        data={
            "username": "admin",
            "password": "correct horse battery staple",
            "request_token": hidden(page, "request_token"),
            "csrf": hidden(page, "csrf"),
        },
    )
    response = client.post(
        "/oauth/authorize",
        data={
            "decision": "deny",
            "request_token": hidden(consent, "request_token"),
            "csrf": hidden(consent, "csrf"),
        },
        follow_redirects=False,
    )
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert (
        query["error"] == ["access_denied"]
        and query["state"] == ["opaque-state"]
        and query["iss"] == ["https://mcp.example"]
    )


def test_15_code_exchange_issues_valid_rs256_tokens(oauth_app):
    client, settings = oauth_app
    client_id = register(client).json()["client_id"]
    response = exchange(client, client_id, authorize_code(client, client_id))
    assert response.status_code == 200 and response.json()["token_type"] == "Bearer"
    claims = jwt.decode(
        response.json()["access_token"],
        settings.oauth_signing_public_key_path.read_bytes(),
        algorithms=["RS256"],
        audience=settings.resource,
        issuer=settings.issuer,
    )
    assert claims["client_id"] == client_id and claims["scope"]


def test_16_authorization_code_is_single_use(oauth_app):
    client, _ = oauth_app
    client_id = register(client).json()["client_id"]
    code = authorize_code(client, client_id)
    assert exchange(client, client_id, code).status_code == 200
    assert exchange(client, client_id, code).json()["error"] == "invalid_grant"


def test_17_wrong_pkce_verifier_is_rejected(oauth_app):
    client, _ = oauth_app
    client_id = register(client).json()["client_id"]
    response = exchange(client, client_id, authorize_code(client, client_id), "x" * 64)
    assert response.json()["error"] == "invalid_grant"


def test_18_refresh_rotation_and_reuse_detection(oauth_app):
    client, _ = oauth_app
    scope = "openid email offline_access accounts.read mail.read"
    client_id = register(client, scope=scope).json()["client_id"]
    first = exchange(client, client_id, authorize_code(client, client_id, scope)).json()
    rotated = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": first["refresh_token"],
        },
    )
    assert (
        rotated.status_code == 200
        and rotated.json()["refresh_token"] != first["refresh_token"]
    )
    reused = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": first["refresh_token"],
        },
    )
    assert (
        reused.json()["error"] == "invalid_grant"
        and "reuse" in reused.json()["error_description"].lower()
    )


def test_19_userinfo_requires_openid_and_returns_email(oauth_app):
    client, _ = oauth_app
    client_id = register(client).json()["client_id"]
    token = exchange(client, client_id, authorize_code(client, client_id)).json()[
        "access_token"
    ]
    response = client.get(
        "/oauth/userinfo", headers={"Authorization": f"Bearer {token}"}
    )
    assert (
        response.status_code == 200 and response.json()["email"] == "admin@example.com"
    )


def test_20_revocation_invalidates_access_token(oauth_app):
    client, _ = oauth_app
    client_id = register(client).json()["client_id"]
    issued = exchange(client, client_id, authorize_code(client, client_id)).json()
    assert (
        client.post(
            "/oauth/revoke",
            data={"client_id": client_id, "token": issued["access_token"]},
        ).status_code
        == 200
    )
    assert (
        client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {issued['access_token']}"},
        ).status_code
        == 401
    )
