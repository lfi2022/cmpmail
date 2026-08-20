const path = require("path");
const python = process.platform === "win32"
  ? path.join(__dirname, ".venv", "Scripts", "python.exe")
  : path.join(__dirname, ".venv", "bin", "python");

module.exports = {
  apps: [{
    name: "lfinfo-mail-mcp",
    script: python,
    args: "-m uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips=10.0.100.2",
    cwd: __dirname,
    interpreter: "none",
    autorestart: true,
    watch: false,
    max_restarts: 10,
    restart_delay: 3000,
    kill_timeout: 15000,
    listen_timeout: 15000,
    time: true,
    merge_logs: true,
    out_file: path.join(__dirname, "logs", "mcp-out.log"),
    error_file: path.join(__dirname, "logs", "mcp-error.log"),
    env: { PYTHONUNBUFFERED: "1" }
  }]
};
