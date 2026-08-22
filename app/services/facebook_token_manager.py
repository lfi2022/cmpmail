"""Facebook User Access Token management with automatic exchange and renewal."""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.config import get_settings
from app.database import SessionLocal
from app.models import SystemSetting
from app.security import CredentialCipher
from app.services.facebook import FacebookAPIError

logger = logging.getLogger(__name__)


class FacebookTokenManager:
    """Manages Facebook user access token lifecycle (short-lived → long-lived)."""

    STORAGE_KEY = "facebook_user_token"
    GRAPH_API_BASE = "https://graph.facebook.com"

    def __init__(self, settings=None):
        self.settings = settings or get_settings()

    @property
    def _cipher(self) -> CredentialCipher:
        return CredentialCipher(self.settings.encryption_key)

    async def exchange_short_lived_token(self, short_token: str) -> tuple[str, datetime]:
        """
        Exchange a short-lived user access token for a long-lived one.

        Args:
            short_token: The short-lived user access token from Facebook

        Returns:
            Tuple of (long_lived_token, expiry_datetime)

        Raises:
            FacebookAPIError: If token exchange fails
        """
        if not self.settings.facebook_app_id or not self.settings.facebook_app_secret:
            raise ValueError("FACEBOOK_APP_ID and FACEBOOK_APP_SECRET must be configured")

        if not short_token or not short_token.strip():
            raise ValueError("short_token cannot be empty")

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.GRAPH_API_BASE}/{self.settings.facebook_graph_api_version}/oauth/access_token",
                    params={
                        "grant_type": "fb_exchange_token",
                        "client_id": self.settings.facebook_app_id,
                        "client_secret": self.settings.facebook_app_secret,
                        "fb_exchange_token": short_token,
                    },
                )
        except httpx.RequestError as e:
            logger.error(f"Network error during token exchange: {e.__class__.__name__}")
            raise FacebookAPIError(f"Failed to reach Facebook API: {e.__class__.__name__}")

        if response.is_error:
            try:
                payload = response.json()
            except ValueError:
                payload = {"error": {"message": response.text}}

            error = payload.get("error", {})
            error_code = error.get("code")
            error_msg = error.get("message", "Unknown error")

            # Handle token expiration error
            if error_code == 190:
                logger.warning("Token exchange failed: token expired or invalid")
                raise FacebookAPIError(
                    "Token has expired or is invalid. Please provide a fresh short-lived token."
                )

            logger.error(f"Token exchange failed: {error_code} - {error_msg}")
            raise FacebookAPIError(f"Token exchange failed: {error_msg}")

        try:
            payload = response.json()
        except ValueError as e:
            logger.error(f"Invalid JSON response from Facebook: {e}")
            raise FacebookAPIError("Invalid response from Facebook API")

        access_token = payload.get("access_token")
        expires_in = payload.get("expires_in")  # seconds

        if not access_token:
            logger.error("No access_token in Facebook response")
            raise FacebookAPIError("No access token in response from Facebook")

        # Store long-lived token and calculate expiry
        expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in or 5184000)  # 60 days default
        await self._store_token(access_token, expiry)

        logger.info("Successfully exchanged Facebook user token; expiry=%s", expiry.isoformat())
        return access_token, expiry

    async def get_long_lived_token(self) -> tuple[str | None, datetime | None]:
        """
        Get the stored long-lived token and its expiry.

        Returns:
            Tuple of (token, expiry) or (None, None) if not available
        """
        stored = await self._load_token_data()
        if stored and (stored.get("encrypted_token") or stored.get("token")):
            encrypted_token = str(stored.get("encrypted_token") or "").strip()
            legacy_plaintext = not encrypted_token
            token = (
                self._cipher.decrypt(encrypted_token)
                if encrypted_token
                else str(stored.get("token", "")).strip()
            )
            expiry_str = stored.get("expiry")
            if token and expiry_str:
                try:
                    expiry = datetime.fromisoformat(expiry_str)
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if legacy_plaintext:
                        await self._store_token(token, expiry)
                    return token, expiry
                except ValueError:
                    logger.warning("Invalid expiry format in stored token data")
        return None, None

    async def is_token_valid(self) -> bool:
        """Check if the long-lived token is still valid (not expired)."""
        token, expiry = await self.get_long_lived_token()
        if not token or not expiry:
            return False

        # Consider token valid if it expires in > 1 hour
        return expiry > datetime.now(timezone.utc) + timedelta(hours=1)

    async def is_token_expired(self) -> bool:
        """Check if the long-lived token has expired."""
        token, expiry = await self.get_long_lived_token()
        if not token or not expiry:
            return True

        return expiry <= datetime.now(timezone.utc)

    async def get_token_status(self) -> dict[str, Any]:
        """Get detailed token status without exposing the token itself."""
        token, expiry = await self.get_long_lived_token()

        if not token:
            return {"has_token": False, "status": "no_token", "expiry": None}

        now = datetime.now(timezone.utc)
        if expiry <= now:
            return {"has_token": True, "status": "expired", "expiry": expiry.isoformat()}

        seconds_remaining = (expiry - now).total_seconds()
        days_remaining = seconds_remaining / 86400

        if days_remaining < 1:
            status = "expiring_soon"
        elif days_remaining < 7:
            status = "expiring_week"
        else:
            status = "valid"

        return {
            "has_token": True,
            "status": status,
            "expiry": expiry.isoformat(),
            "days_remaining": round(days_remaining, 1),
        }

    async def clear_token(self):
        """Clear the stored long-lived token."""
        async with SessionLocal() as db:
            setting = await db.get(SystemSetting, self.STORAGE_KEY)
            if setting:
                await db.delete(setting)
                await db.commit()
        logger.info("Cleared long-lived token storage")

    # Private methods

    async def _store_token(self, token: str, expiry: datetime) -> None:
        """Store the long-lived token and expiry in the database."""
        async with SessionLocal() as db:
            setting = await db.get(SystemSetting, self.STORAGE_KEY)
            if not setting:
                setting = SystemSetting(key=self.STORAGE_KEY)

            setting.value = {
                "encrypted_token": self._cipher.encrypt(token),
                "expiry": expiry.isoformat(),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
            db.add(setting)
            await db.commit()

    async def _load_token_data(self) -> dict[str, Any] | None:
        """Load token data from the database."""
        async with SessionLocal() as db:
            setting = await db.get(SystemSetting, self.STORAGE_KEY)
            if setting and isinstance(setting.value, dict):
                return setting.value
        return None
