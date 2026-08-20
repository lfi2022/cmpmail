# Installation production

Prérequis : Linux, Python 3.12+, Node.js 20+ pour compiler l'interface, PM2 et un reverse proxy HTTPS.

```bash
cd /opt
git clone REPOSITORY lfinfo-mail-mcp
cd lfinfo-mail-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
cp .env.example .env
nano .env
mkdir -p logs data
python scripts/generate-oauth-secrets.py
alembic upgrade head
pm2 start ecosystem.config.js
pm2 save
pm2 startup
```

Remplacez chaque `A_REMPLIR`. Générez les clés localement :

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Le script OAuth affiche le hash Argon2id et les chemins de clés à reporter dans `.env`. Il ne faut jamais committer le dossier `secrets/`. Voir [OAUTH.md](OAUTH.md).

Contrôles :

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/ready
curl http://127.0.0.1:8000/version
pm2 status
```

`/ready` reste en 503 tant que la configuration, la DB ou un compte actif manque. C'est volontaire.
