# Mailcow

Configuration recommandée : IMAP `mail.example.com:993` avec TLS implicite; SMTP `mail.example.com:465` avec TLS implicite, ou port 587 avec STARTTLS et TLS implicite désactivé. L'utilisateur est généralement l'adresse complète.

Exemple LFINFO sans secret :

```text
PUBLIC_URL=https://mcp.lfinfo.be
Reverse proxy=10.0.100.2
Mailcow public/TLS=mail.lfinfo.be
Mailcow interne=10.0.200.4
IMAPS=993
SMTPS=465
```

Pour éviter le NAT loopback, configurez le DNS local ou `/etc/hosts` du serveur MCP : `10.0.200.4 mail.lfinfo.be`. Gardez impérativement `mail.lfinfo.be` comme hostname configuré : le certificat TLS lui est délivré. Ne configurez pas `10.0.200.4` comme hostname TLS.

Après ajout, utilisez « Détecter les dossiers » : le serveur lit les attributs RFC 6154 `\\Sent`, `\\Drafts`, `\\Trash`, `\\Archive`, `\\Junk`.

