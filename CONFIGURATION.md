# Configuration

Le backend charge `.env`; les secrets ne sont jamais placés dans PM2 ni dans la base. `DATABASE_URL` accepte SQLite (`sqlite+aiosqlite:///./data/mailmcp.db`) et PostgreSQL (`postgresql+asyncpg://user:pass@host/db`).

Variables essentielles :

| Variable | Rôle |
|---|---|
| `PUBLIC_URL`, `MCP_PATH` | URL publique calculée et chemin MCP |
| `SECRET_KEY` | signature des sessions admin et jetons CSRF |
| `ENCRYPTION_KEY` | chiffrement Fernet des mots de passe mail |
| `MCP_AUTH_ENABLED`, `OAUTH_ENABLED` | authentification OAuth du endpoint MCP |
| `OAUTH_ISSUER`, `OAUTH_RESOURCE` | émetteur public et audience MCP exacte |
| `OAUTH_SIGNING_KEY_PATH`, `OAUTH_SIGNING_PUBLIC_KEY_PATH`, `OAUTH_SIGNING_KID` | signature JWT RS256 et publication JWKS |
| `ADMIN_USERNAME`, `ADMIN_EMAIL`, `ADMIN_PASSWORD_HASH` | utilisateur local Argon2id initial |
| `MCP_LEGACY_API_KEY_ENABLED`, `MCP_API_KEY` | compatibilité historique, désactivée par défaut |
| `ALLOWED_HOSTS` | protection Host/DNS rebinding |
| `ALLOWED_ORIGINS` | origines navigateur autorisées |
| `TRUSTED_PROXIES` | IP/CIDR autorisés à fournir `X-Forwarded-For` |
| `READ_ONLY` | bloque les mutations MCP |
| `ALLOW_COPY_IN_READ_ONLY` | seule exception possible au mode lecture seule |
| `DESTRUCTIVE_OPERATIONS_ENABLED` | coupe les EXPUNGE permanents |
| `MAX_REQUEST_SIZE_MB`, `MAX_ATTACHMENT_SIZE_MB`, `MAX_RAW_MESSAGE_SIZE_MB` | limites mémoire et données |
| `ATTACHMENT_SAVE_DIR`, `BLOCKED_ATTACHMENT_TYPES` | racine contrôlée et types MIME interdits |

Après toute modification : `pm2 restart lfinfo-mail-mcp --update-env`.

Les réglages réseau/de sécurité sont lus au démarrage : leur modification dans l'UI est volontairement informative, car une mutation à chaud fragiliserait le middleware actif. Les comptes et clés API sont modifiables en ligne.
