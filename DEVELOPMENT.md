# Développement et tests

Backend : `uvicorn app.main:app --reload --host 127.0.0.1 --port 8000`. Frontend : `cd frontend && npm run dev`; Vite proxyfie `/api` et `/mcp`.

Qualité :

```bash
ruff check app tests
pytest -q
cd frontend
npm run build
npm run test
```

Tests d'intégration : utilisez exclusivement un compte isolé et le préfixe `MCP_TEST_`. Variables suggérées : `MCP_TEST_IMAP_HOST`, `MCP_TEST_IMAP_PORT`, `MCP_TEST_SMTP_HOST`, `MCP_TEST_SMTP_PORT`, `MCP_TEST_USERNAME`, `MCP_TEST_PASSWORD`. Ils doivent créer/nettoyer `MCP_TEST_FOLDER`, envoyer en self-to-self, comparer Message-ID Inbox/Sent et retrouver les MOVE par Message-ID. Aucun test destructif n'est lancé sans opt-in explicite.

Une migration doit accompagner toute évolution de modèle : `alembic revision --autogenerate -m "description"`, relire le fichier, puis `alembic upgrade head`.
