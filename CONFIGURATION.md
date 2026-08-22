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
| `TEMPORARY_UPLOAD_DIR`, `TEMPORARY_UPLOAD_TTL_MINUTES` | stockage local et durée de vie des images temporaires; TTL par défaut: 10 minutes |
| `ATTACHMENT_SAVE_DIR`, `BLOCKED_ATTACHMENT_TYPES` | racine contrôlée et types MIME interdits |

Après toute modification : `pm2 restart lfinfo-mail-mcp --update-env`.

Les réglages réseau/de sécurité sont lus au démarrage : leur modification dans l'UI est volontairement informative, car une mutation à chaud fragiliserait le middleware actif. Les comptes et clés API sont modifiables en ligne.

## Facebook Pages

| Variable | Rôle |
|---|---|
| `FACEBOOK_APP_ID` | Identifiant de l'application Meta, utilisé uniquement côté serveur |
| `FACEBOOK_APP_SECRET` | Secret Meta, uniquement dans `.env` |
| `FACEBOOK_USER_ACCESS_TOKEN` | Fallback de déploiement ; privilégier l'échange depuis l'interface admin |
| `FACEBOOK_DEFAULT_PAGE_ID` | Page utilisée quand `page_id` est omis |
| `FACEBOOK_GRAPH_API_VERSION` | Version Graph API à utiliser, par exemple `v19.0` |

L'interface admin reçoit un User Access Token courte durée, l'échange côté serveur contre un token longue durée via `fb_exchange_token`, puis stocke seulement sa version chiffrée avec `ENCRYPTION_KEY` et sa date d'expiration. Les Page Access Tokens sont récupérés dynamiquement via `/me/accounts` et ne sont jamais renvoyés par les APIs d'administration ou les tools MCP.

Les scopes MCP requis sont `facebook.read`, `facebook.write` et `facebook.moderate`. Les permissions Meta correspondantes doivent être accordées à l'application et au compte administrateur de la Page. Certaines fonctionnalités, en particulier les notifications et les métriques Insights, dépendent de permissions et de métriques toujours disponibles dans la version Graph API configurée ; les erreurs Meta sont renvoyées explicitement sans faux succès.

L'outil `upload_temporary_image` accepte les images JPEG, PNG et WEBP jusqu'à 10 MiB et renvoie une URL publique temporaire basée sur `PUBLIC_URL`. Cette URL est volontairement accessible sans authentification pour permettre son téléchargement par Meta. Configurez `PUBLIC_URL` avec l'URL HTTPS publique du serveur; les fichiers sont purgés après 10 minutes par défaut. `facebook_create_photo_post` accepte aussi `temporary_file_id` et supprime le fichier après l'appel Facebook.
