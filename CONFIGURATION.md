# Configuration

Le backend charge `.env`; les secrets ne sont jamais placés dans PM2 ni dans la base. `DATABASE_URL` accepte SQLite (`sqlite+aiosqlite:///./data/mailmcp.db`) et PostgreSQL (`postgresql+asyncpg://user:pass@host/db`).

Variables essentielles :

| Variable | Rôle |
|---|---|
| `PUBLIC_URL`, `MCP_PATH` | URL publique calculée et chemin MCP |
| `SECRET_KEY` | signature des sessions admin et jetons CSRF |
| `ENCRYPTION_KEY` | chiffrement Fernet des mots de passe mail |
| `MCP_AUTH_ENABLED`, `MCP_API_KEY` | authentification MCP globale |
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
