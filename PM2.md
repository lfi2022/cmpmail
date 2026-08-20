# PM2

`ecosystem.config.js` supervise l'unique processus Uvicorn. Les secrets restent dans `.env`, chargé par l'application.

```bash
npm run pm2:start
npm run pm2:status
npm run pm2:logs
npm run pm2:reload
npm run pm2:restart
npm run pm2:stop
pm2 save
```

Après changement de `.env` : `pm2 restart lfinfo-mail-mcp --update-env`.

Rotation :

```bash
pm2 install pm2-logrotate
pm2 set pm2-logrotate:max_size 20M
pm2 set pm2-logrotate:retain 14
pm2 set pm2-logrotate:compress true
```

Les sorties sont `logs/mcp-out.log`, `logs/mcp-error.log`; les événements sensibles sont conservés dans la table audit et peuvent en complément être expédiés vers `logs/audit.log` par votre collecteur.

