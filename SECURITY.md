# Sécurité

- Les mots de passe IMAP/SMTP sont chiffrés par Fernet avec `ENCRYPTION_KEY`, absente de la DB.
- Les clés créées dans l'UI sont stockées sous forme Argon2 et affichées une seule fois.
- MCP accepte `Authorization: Bearer …` ou `X-API-Key`.
- Permissions : `read`, `send`, `move`, `copy`, `flags`, `delete`, `folders`, `attachments`, `admin`.
- L'administration utilise un cookie HttpOnly, `SameSite=Strict`, Secure et un double jeton CSRF.
- `ALLOWED_HOSTS` protège contre le DNS rebinding. N'utilisez jamais `*` en production.
- Les en-têtes forwardés ne sont honorés que depuis `TRUSTED_PROXIES`.
- Les corps de mails ne sont pas journalisés. Les secrets retournés par l'API sont masqués.
- `save_attachment` ne prend aucun chemin arbitraire : le payload contrôlé est retourné au client.

Conservez `.env` en mode 600, sauvegardez `data/` de façon chiffrée, faites tourner les clés, restreignez le port 8000 au reverse proxy et activez TLS public. En cas de rotation d'`ENCRYPTION_KEY`, rechiffrez les credentials avant de retirer l'ancienne clé.

`delete_email_permanently`, `delete_emails_permanently` et `delete_mailbox` sont destructifs. Désactivez-les via `DESTRUCTIVE_OPERATIONS_ENABLED=false` ou utilisez `READ_ONLY=true`.

