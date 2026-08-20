# LFINFO Mail MCP

Serveur MCP Mail self-hosted réunissant, dans un seul processus FastAPI, une interface React, une API d'administration et un transport MCP Streamable HTTP natif. Il cible Mailcow et fonctionne avec tout service IMAP/SMTP standard.

## Points clés

- `/mcp` : SDK MCP Python officiel, Streamable HTTP, sessions et JSON/SSE.
- `/` : console d'administration React compilée et servie par FastAPI.
- `/api` : comptes, dossiers, messages, clés, logs, audit et diagnostics.
- `/health`, `/ready`, `/version` : supervision.
- IMAP : dossiers RFC 6154, delimiter réel, recherche, MIME, flags, MOVE/COPY avec remappage UID, drafts et suppression explicite.
- SMTP : TLS/STARTTLS, Message-ID généré avant envoi et copie identique dans Sent.
- Sécurité : OAuth 2.1/OIDC, PKCE S256, JWT RS256/JWKS, refresh rotation, scopes, sessions HttpOnly, CSRF, trusted hosts, CORS, rate limit et limites de taille.

Installation rapide : voir [INSTALL.md](INSTALL.md). OAuth : [OAUTH.md](OAUTH.md). Connexion ChatGPT : [CHATGPT.md](CHATGPT.md). Outils : [MCP_TOOLS.md](MCP_TOOLS.md).

## Développement

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

Dans un second terminal :

```bash
cd frontend
npm install
npm run dev
```

Ne démarrez pas Vite en production. Compilez-le avec `npm run build`, puis PM2 lance uniquement FastAPI.
