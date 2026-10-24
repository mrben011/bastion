#!/usr/bin/env bash
# One-command local test environment for Mac, Linux, or Windows WSL. Requires Docker.
# Usage: ./scripts/setup.sh [admin-email]
set -euo pipefail
cd "$(dirname "$0")/.."

ADMIN_EMAIL="${1:-admin@example.com}"
ORG_NAME="Demo Organization"

command -v docker >/dev/null || { echo "Docker is not installed. Get Docker Desktop: https://docs.docker.com/get-docker/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required (it ships with Docker Desktop)."; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required to generate secrets."; exit 1; }

rand() { openssl rand -base64 24 | tr -d '/+=\n'; }

if [ -f .env ]; then
  echo "Keeping your existing .env"
else
  cat > .env <<ENV
DB_OWNER_PASSWORD=$(rand)
DB_APP_PASSWORD=$(rand)
FIELD_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n')
# Local testing over plain http. Set to true when you put HTTPS in front.
COOKIE_SECURE=false
ALLOWED_ORIGIN=http://localhost:8080
ENV
  chmod 600 .env
fi

echo "Building and starting (the first run takes a few minutes)..."
docker compose up -d --build

echo "Waiting for the API..."
for _ in $(seq 1 90); do
  if curl -fs http://localhost:8080/api/readyz >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -fs http://localhost:8080/api/readyz >/dev/null || { echo "API did not become ready. Run: docker compose logs api migrate"; exit 1; }

ADMIN_PW="$(rand)"
DEMO_PW="$(rand)"
docker compose run --rm -T -e BASTION_BOOTSTRAP_PASSWORD="$ADMIN_PW" migrate \
  python -m app.cli bootstrap --org-name "$ORG_NAME" --admin-email "$ADMIN_EMAIL"
docker compose run --rm -T -e BASTION_DEMO_PASSWORD="$DEMO_PW" migrate \
  python -m app.cli seed-demo --org-name "$ORG_NAME"

umask 077
cat > .local-credentials.txt <<CRED
Open:        http://localhost:8080
Admin:       $ADMIN_EMAIL
Password:    $ADMIN_PW
(you will be asked to set up an authenticator app on first sign-in)

Sample users (temporary password, must be changed at first sign-in):
  analyst.demo@example.com
  responder.demo@example.com
  auditor.demo@example.com
Temporary password: $DEMO_PW
CRED

echo
cat .local-credentials.txt
echo
echo "Saved to .local-credentials.txt (keep it private). Stop with: docker compose down. Wipe everything with: docker compose down -v"
