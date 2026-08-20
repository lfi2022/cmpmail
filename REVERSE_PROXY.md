# Reverse proxy

Le reverse proxy termine HTTPS et joint FastAPI en HTTP sur `:8000`. Un exemple Nginx est disponible dans `deploy/nginx.conf`. Pour Nginx Proxy Manager/OpenResty, désactivez le buffering, activez WebSocket/HTTP 1.1 et passez Host, X-Real-IP, X-Forwarded-For et X-Forwarded-Proto. Caddy et Traefik gèrent le streaming automatiquement mais doivent conserver Host.

Pare-feu : autorisez `10.0.100.2 -> serveur MCP:8000` seulement. Déclarez `TRUSTED_PROXIES=10.0.100.2`, `ALLOWED_HOSTS=localhost,127.0.0.1,mcp.lfinfo.be` et `ALLOWED_ORIGINS=https://mcp.lfinfo.be`.

Validation externe :

```bash
curl -i https://mcp.lfinfo.be/health
curl -i -X POST https://mcp.lfinfo.be/mcp \
  -H 'Authorization: Bearer VOTRE_CLE' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"external-test","version":"1.0"}}}'
```

