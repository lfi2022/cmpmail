# Connexion depuis ChatGPT

Préconditions : le domaine `mcp.lfinfo.be` doit présenter un certificat public valide, répondre directement en HTTPS et ne pas déclencher de redirection vers une autre origine.

1. Dans les paramètres des connecteurs/apps ChatGPT, ajoutez un serveur MCP distant.
2. Indiquez `https://mcp.lfinfo.be/mcp` comme URL MCP et choisissez OAuth lorsqu’il est proposé.
3. ChatGPT découvre automatiquement les métadonnées de ressource et d’autorisation, puis inscrit un client public via DCR.
4. Connectez-vous sur la page LFINFO, examinez précisément les scopes demandés et donnez votre consentement.
5. Testez d’abord une lecture. Les envois, déplacements et suppressions nécessitent leurs scopes explicites.

Diagnostic rapide :

```bash
curl -i https://mcp.lfinfo.be/.well-known/oauth-protected-resource
curl -i https://mcp.lfinfo.be/.well-known/oauth-authorization-server
curl -i https://mcp.lfinfo.be/.well-known/openid-configuration
curl -i https://mcp.lfinfo.be/.well-known/jwks.json
curl -i https://mcp.lfinfo.be/mcp
```

Le dernier appel doit retourner `401` avec un en-tête `WWW-Authenticate` contenant `resource_metadata`. Un échec `invalid_target` indique généralement que `OAUTH_RESOURCE` diffère de l’URL MCP. Un échec de callback indique une URI non enregistrée exactement. Si ChatGPT demande un nouveau consentement, vérifiez que les sessions ou le client n’ont pas été révoqués dans l’administration.

Pour tolérer un connecteur créé avec `https://mcp.lfinfo.be` sans suffixe, `POST /` est également acheminé vers le transport MCP. `GET /` continue de servir exclusivement l’interface d’administration. L’URL canonique à utiliser reste `https://mcp.lfinfo.be/mcp`.
