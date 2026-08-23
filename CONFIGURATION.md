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
| `TEMPORARY_UPLOAD_DIR`, `TEMPORARY_UPLOAD_TTL_MINUTES`, `TEMPORARY_UPLOAD_MAX_BYTES`, `TEMPORARY_UPLOAD_MAX_BASE64_BYTES` | stockage, durée de vie et limites des images temporaires; TTL par défaut: 10 minutes |
| `TEMPORARY_UPLOAD_OPTIMIZE`, `TEMPORARY_UPLOAD_MAX_DIMENSION`, `TEMPORARY_UPLOAD_JPEG_QUALITY` | optimisation des images; largeur/hauteur maximale 1600 px et qualité JPEG 85 par défaut |
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

L'outil `upload_temporary_image` accepte les images JPEG, PNG et WEBP jusqu'à 10 MiB et renvoie une URL publique temporaire basée sur `PUBLIC_URL`. Cette URL est volontairement accessible sans authentification pour permettre son téléchargement par Meta. Configurez `PUBLIC_URL` avec l'URL HTTPS publique du serveur; les fichiers sont purgés après 10 minutes par défaut. Pillow optimise les images réelles de grande taille (maximum 1600 px, qualité JPEG 85) sans agrandir les petites images; `facebook_create_photo_post` accepte aussi `temporary_file_id` et supprime le fichier après l'appel Facebook.

## Dolibarr

| Variable | Rôle |
|---|---|
| `DOLIBARR_API_URL` | URL de base de l'API REST Dolibarr, ex. `https://erp.example.com/api/index.php` |
| `DOLIBARR_API_KEY` | Jeton `DOLAPIKEY` généré sur la fiche d'un utilisateur Dolibarr (module API REST activé) |
| `DOLIBARR_TIMEOUT_SECONDS` | Timeout HTTP par requête, défaut `30` |
| `DOLIBARR_VERIFY_SSL` | Vérification du certificat TLS, défaut `true` |

Le module s'appuie sur l'API REST officielle de Dolibarr (module `API REST`, framework Restler) : chaque ressource suit le schéma `GET/POST /{resource}`, `GET/PUT/DELETE /{resource}/{id}` et des sous-actions documentées comme `/invoices/{id}/validate`. L'authentification se fait par l'en-tête HTTP `DOLAPIKEY`, jamais en paramètre d'URL. Les scopes MCP sont `dolibarr.read`, `dolibarr.write` et `dolibarr.delete`; ce dernier respecte `DESTRUCTIVE_OPERATIONS_ENABLED` et `READ_ONLY`. Les outils `dolibarr_list`/`dolibarr_get`/`dolibarr_create`/`dolibarr_update`/`dolibarr_delete`/`dolibarr_action` sont génériques et couvrent tout module Dolibarr exposant une classe API (`api_<module>.class.php`); `dolibarr_list_resources` fournit un catalogue indicatif des ressources courantes.

## Nextcloud

| Variable | Rôle |
|---|---|
| `NEXTCLOUD_URL` | URL de base de l'instance, ex. `https://cloud.example.com` |
| `NEXTCLOUD_USERNAME` | Identifiant du compte Nextcloud géré |
| `NEXTCLOUD_APP_PASSWORD` | Mot de passe d'application généré dans Paramètres de sécurité > Appareils et sessions (jamais le mot de passe principal, révocable indépendamment) |
| `NEXTCLOUD_TIMEOUT_SECONDS` | Timeout HTTP par requête, défaut `30` |
| `NEXTCLOUD_VERIFY_SSL` | Vérification du certificat TLS, défaut `true` |
| `NEXTCLOUD_MAX_DOWNLOAD_MB` / `NEXTCLOUD_MAX_UPLOAD_MB` | Limites de taille pour les transferts en base64, défaut `25` |

Le module combine WebDAV (fichiers, dossiers, corbeille) et l'API OCS (partages, profil, capabilities) du compte personnel configuré, en authentification HTTP Basic avec le mot de passe d'application. Les scopes MCP sont `nextcloud.read`, `nextcloud.write` et `nextcloud.delete`; ce dernier respecte `DESTRUCTIVE_OPERATIONS_ENABLED`. La suppression normale (`nextcloud_delete`) passe par la corbeille Nextcloud et reste récupérable; seule `nextcloud_delete_trash_item` est irréversible. Les outils génériques `nextcloud_webdav_request` et `nextcloud_ocs_request` couvrent tout endpoint non exposé par un outil dédié (verrouillage, notifications, groupes, etc.). Les fragments d'authentification Basic sont systématiquement retirés des messages d'erreur journalisés. Le jeton et les clés (`dolapikey`, `token`) sont systématiquement retirés des réponses et des messages d'erreur journalisés.

