# Sécurité

## Modèle d'authentification

MCP utilise OAuth 2.1/OIDC avec Authorization Code et PKCE S256 obligatoire. Les access tokens sont des JWT RS256 à audience et émetteur stricts; leur `jti` et leur session sont contrôlés à chaque requête. Les refresh tokens et codes sont aléatoires, stockés uniquement sous forme SHA-256 et à usage unique. Consultez [OAUTH.md](OAUTH.md).

La session d'administration et la session de connexion OAuth sont séparées. Les mots de passe locaux sont hachés avec Argon2id, les formulaires sensibles ont un jeton CSRF signé et les tentatives sont limitées puis verrouillées. Les clés privées, `.env`, jetons, codes et secrets clients ne doivent jamais entrer dans Git ni dans les logs.

## Exposition réseau

Terminez TLS sur le reverse proxy `10.0.100.2`, transmettez un `Host` inchangé et `X-Forwarded-For`, et bloquez l'accès direct au port FastAPI depuis Internet. Seules les adresses de `TRUSTED_PROXIES` sont autorisées à influencer l'IP journalisée. Le serveur ajoute HSTS en production, CSP, `nosniff`, `DENY` pour les frames et une politique de permissions restrictive.

Les endpoints `/.well-known/*`, `/oauth/*`, `/health`, `/ready`, `/version` et `/mcp` doivent parvenir sans authentification intermédiaire Cloudflare Access. Les règles WAF/rate-limit peuvent les protéger, mais ne doivent ni réécrire les paramètres OAuth ni mettre en cache les réponses de jetons. N'activez pas de contournement TLS entre le proxy et une origine non maîtrisée.

La directive CSP `form-action` autorise les destinations HTTPS, car un consentement OAuth se termine nécessairement par une redirection vers le client. Cette permission CSP ne décide jamais de la destination : l'API OAuth exige toujours une correspondance exacte avec une URI préalablement enregistrée.

## Réponse à incident

Révoquez le client ou la session dans l'interface, puis recherchez les événements `oauth.*` dans Audit. En cas de fuite de clé privée, générez une nouvelle paire, changez le `kid`, redémarrez, révoquez toutes les sessions et considérez tous les access tokens non expirés comme compromis. En cas de réutilisation de refresh token, la famille est automatiquement invalidée.

- Les mots de passe IMAP/SMTP sont chiffrés par Fernet avec `ENCRYPTION_KEY`, absente de la DB.
- Les clés créées dans l'UI sont stockées sous forme Argon2 et affichées une seule fois.
- MCP accepte les access tokens via `Authorization: Bearer …`. Les clés historiques ne sont acceptées que si `MCP_LEGACY_API_KEY_ENABLED=true`.
- Permissions : `read`, `send`, `move`, `copy`, `flags`, `delete`, `folders`, `attachments`, `admin`.
- L'administration utilise un cookie HttpOnly, `SameSite=Strict`, Secure et un double jeton CSRF.
- `ALLOWED_HOSTS` protège contre le DNS rebinding. N'utilisez jamais `*` en production.
- Les en-têtes forwardés ne sont honorés que depuis `TRUSTED_PROXIES`.
- Les corps de mails ne sont pas journalisés. Les secrets retournés par l'API sont masqués.
- `save_attachment` ne prend aucun chemin arbitraire : le payload contrôlé est retourné au client.

Conservez `.env` en mode 600, sauvegardez `data/` de façon chiffrée, faites tourner les clés, restreignez le port 8000 au reverse proxy et activez TLS public. En cas de rotation d'`ENCRYPTION_KEY`, rechiffrez les credentials avant de retirer l'ancienne clé.

`delete_email_permanently`, `delete_emails_permanently` et `delete_mailbox` sont destructifs. Désactivez-les via `DESTRUCTIVE_OPERATIONS_ENABLED=false` ou utilisez `READ_ONLY=true`.
