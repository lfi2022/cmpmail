# Dépannage

- `/ready` renvoie 503 : lisez `checks`/`errors`, appliquez les migrations, configurez les secrets et activez au moins un compte.
- MCP 401 : fournissez `Authorization: Bearer` ou `X-API-Key`; la clé d'environnement ne fonctionne pas tant qu'elle vaut `A_REMPLIR`.
- MCP 421 : ajoutez le hostname public à `ALLOWED_HOSTS` et redémarrez.
- Erreur TLS Mailcow : utilisez le hostname du certificat, même si le DNS local le résout vers l'IP privée.
- SMTP réussi mais Sent absent : l'envoi reste `success=true`, `saved_to_sent=false` avec warning; détectez/configurez Sent et vérifiez les ACL APPEND.
- MOVE sans `new_uid` : le serveur n'a pu retrouver le Message-ID côté cible; ne réutilisez pas l'UID source.
- Interface 503 : exécutez `cd frontend && npm install && npm run build`.
- Échec de déchiffrement : l'`ENCRYPTION_KEY` ne correspond pas à celle utilisée à la création du compte.

Diagnostic local : `pm2 logs lfinfo-mail-mcp`, `curl -i http://127.0.0.1:8000/health`, puis la page Diagnostics.

