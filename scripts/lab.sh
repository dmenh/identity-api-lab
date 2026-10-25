#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
action="${1:-install}"
database="${2:-auto}"
port="${3:-8787}"
case "$action" in install|start|stop|restart|status|logs|verify|passwords|update) ;; *) echo 'Actions: install start stop restart status logs verify passwords update'; exit 1;; esac
case "$database" in auto|postgres|mysql|sqlite) ;; *) echo 'Databases: auto postgres mysql sqlite'; exit 1;; esac
command -v docker >/dev/null || { echo 'Docker is required.'; exit 1; }
docker info >/dev/null 2>&1 || { echo 'Start Docker, then retry.'; exit 1; }
docker compose version >/dev/null
secret(){ if command -v openssl >/dev/null; then openssl rand -hex 32; else python3 -c 'import secrets;print(secrets.token_hex(32))'; fi; }
read_value(){ sed -n "s/^$1=//p" .env 2>/dev/null | tail -1; }
add_value(){ [ -n "$(read_value "$1")" ] || printf '%s=%s\n' "$1" "$2" >>.env; }
choose_database(){ value="$(read_value LAB_DATABASE)"; [ "$database" = auto ] && database="${value:-postgres}"; }
compose_file(){ case "$database" in mysql) echo compose.mysql.yaml;; sqlite) echo compose.sqlite.yaml;; *) echo compose.yaml;; esac; }
health(){
  app_port="$(read_value APP_PORT)"; count=0
  while [ "$count" -lt 30 ]; do
    if command -v curl >/dev/null && curl -fsS "http://localhost:$app_port/health" >/dev/null 2>&1; then echo "Healthy: http://localhost:$app_port"; return; fi
    count=$((count+1)); sleep 2
  done
  echo 'Health verification failed. Run: sh scripts/lab.sh logs'; exit 1
}
if [ "$action" = install ]; then
  case "$port" in *[!0-9]*|'') echo 'Port must be numeric'; exit 1;; esac
  [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || { echo 'Port must be 1024–65535'; exit 1; }
  if [ ! -f .env ]; then umask 077; : >.env; fi
  [ "$database" = auto ] && database=postgres
  add_value APP_PORT "$port"; add_value GRPC_PORT 50051; add_value APP_BIND 127.0.0.1; add_value LAB_DATABASE "$database"
  add_value DB_PASSWORD "$(secret)"; add_value DB_ROOT_PASSWORD "$(secret)"
  add_value ADMIN_PASSWORD "Lab-$(secret)"; add_value DEMO_PASSWORD "Demo-$(secret)"
  add_value SERVER_SIGNING_KEY "$(secret)"; add_value COOKIE_SECURE false
  add_value ALLOWED_HOSTS 'localhost,127.0.0.1'; add_value ALLOW_PRIVATE_SSO false; add_value ALLOW_INSECURE_SSO false
  add_value ALLOW_PRIVATE_SFTP false; add_value GRPC_ENABLED true
  add_value PUBLIC_URL "http://localhost:$(read_value APP_PORT)"
  file="$(compose_file)"; docker compose -f "$file" config --quiet
  docker compose -f "$file" up -d --build --wait --wait-timeout 240
  health; echo 'Username: admin'; echo 'Run: sh scripts/lab.sh passwords to display generated passwords.'; exit
fi
[ -f .env ] || { echo 'Run the install action first.'; exit 1; }
choose_database; file="$(compose_file)"
case "$action" in
  start) docker compose -f "$file" up -d --wait; health;;
  stop) docker compose -f "$file" stop;;
  restart) docker compose -f "$file" restart; health;;
  status) docker compose -f "$file" ps;;
  logs) docker compose -f "$file" logs --tail 200 -f app;;
  verify) health; python3 scripts/verify_live.py;;
  passwords) printf 'Admin username: admin\nAdmin password: %s\nEmployee demo password: %s\n' "$(read_value ADMIN_PASSWORD)" "$(read_value DEMO_PASSWORD)";;
  update) docker compose -f "$file" up -d --build --pull --wait --wait-timeout 240; health;;
esac
