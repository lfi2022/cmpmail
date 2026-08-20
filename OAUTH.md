# OAuth 2.1 et OpenID Connect

Le serveur MCP est une ressource OAuth protégée. En production, seul le flux `authorization_code` avec PKCE `S256` est accepté. Les mots de passe ne sont jamais échangés avec ChatGPT et les clés API historiques sont désactivées par défaut.

## Préparation

1. Installez les dépendances puis générez les secrets hors du dépôt :

   ```powershell
   python scripts/generate-oauth-secrets.py
   ```

2. Copiez les trois lignes produites dans `.env`. Conservez la clé privée lisible uniquement par le compte du service.
3. Définissez au minimum :

   ```dotenv
   PUBLIC_URL=https://mcp.lfinfo.be
   OAUTH_ISSUER=https://mcp.lfinfo.be
   OAUTH_RESOURCE=https://mcp.lfinfo.be/mcp
   OAUTH_ENABLED=true
   MCP_LEGACY_API_KEY_ENABLED=false
   TRUSTED_PROXIES=10.0.100.2
   SECURE_COOKIES=true
   ```

4. Appliquez `alembic upgrade head`, redémarrez le service et contrôlez `/ready`.

Le premier utilisateur local est créé depuis `ADMIN_USERNAME` et `ADMIN_PASSWORD_HASH`. Le hash est Argon2id. Les sessions OAuth et celles de l’administration utilisent des cookies distincts, `HttpOnly`, `Secure` et limités dans le temps.

## Endpoints

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`
- `/.well-known/openid-configuration`
- `/.well-known/jwks.json`
- `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, `/oauth/userinfo`

L’inscription dynamique RFC 7591 refuse les jokers, fragments et URI non HTTPS, à l’exception de `http://localhost` pour le développement. Une URI de retour doit correspondre octet pour octet. Le paramètre OAuth `resource` doit toujours valoir `https://mcp.lfinfo.be/mcp`.

## Durées et révocation

- code d’autorisation : 5 minutes et usage unique ;
- access token : 15 minutes ;
- refresh token : 30 jours, rotation à chaque usage ;
- session de connexion : 8 heures.

La réutilisation d’un ancien refresh token révoque toute sa famille et la session. L’administration permet aussi de révoquer immédiatement un client ou une session. Les événements de connexion, consentement, émission, rotation, réutilisation et révocation sont audités sans stocker les jetons en clair.

## Rotation des clés JWT

La version actuelle publie une clé active identifiée par `OAUTH_SIGNING_KID`. Pour une rotation sans interruption : déployez d’abord une version publiant l’ancienne et la nouvelle clé dans JWKS, signez ensuite avec le nouveau `kid`, attendez la durée maximale des access tokens, puis retirez l’ancienne clé. Ne remplacez jamais seulement le fichier privé pendant qu’un processus tourne.

## Scopes

Les scopes sont `accounts.read`, `accounts.write`, `mail.read`, `mail.send`, `mail.move`, `mail.copy`, `mail.flags`, `mail.delete`, `mail.folders` et `mail.attachments`. `openid`, `profile`, `email` et `offline_access` couvrent OIDC et le renouvellement. Une opération sans scope retourne `insufficient_scope`; les suppressions permanentes restent soumises au commutateur global des opérations destructives.

