#!/bin/bash

# Instalação em Linux (systemd) — OPSMON com Oracle (JRuby + OJDBC em lib/) + Redis (opcional).
# O utilizador opsmon precisa de JRuby no PATH (rbenv ou pacote do sistema).

set -e

if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "Este install.sh é só para Linux (systemd). No macOS:"
  echo "  rbenv install \$(cat .ruby-version) && rbenv local \$(cat .ruby-version)"
  echo "  cp .env.example .env   # preenche ORACLE_*"
  echo "  bundle install && bundle exec rake db:migrate && bundle exec ruby server.rb"
  exit 1
fi

if [ "$EUID" -ne 0 ]; then
  echo "Executa como root (ex.: sudo ./install.sh)"
  exit 1
fi

echo "Pré-requisitos:"
echo "  - Oracle DB acessível (ORACLE_* no .env)"
echo "  - Migrações: como utilizador opsmon, após bundle install: bundle exec rake db:migrate"
echo "  - Redis opcional (rate limit / API keys)"
echo ""

if ! getent group opsmon >/dev/null; then
  groupadd opsmon
fi

if ! getent passwd opsmon >/dev/null; then
  useradd -g opsmon -m -s /bin/bash opsmon
fi

INSTALL_DIR="/opt/opsmon"
mkdir -p "$INSTALL_DIR"

cp -r . "$INSTALL_DIR/"
chown -R opsmon:opsmon "$INSTALL_DIR"

cd "$INSTALL_DIR"

if [ -f "$INSTALL_DIR/.bundle/config" ]; then
  su - opsmon -s /bin/bash -c "cd $INSTALL_DIR && bundle install"
else
  su - opsmon -s /bin/bash -c "cd $INSTALL_DIR && bundle config set path 'vendor/bundle' && bundle install"
fi

su - opsmon -s /bin/bash -c "cd $INSTALL_DIR && bundle exec rake db:migrate" || {
  echo "Aviso: rake db:migrate falhou — executa manualmente após configurar Oracle."
}

mkdir -p /var/log/opsmon
chown opsmon:opsmon /var/log/opsmon

if [ -f "$INSTALL_DIR/settings/config/opsmon.service" ]; then
  cp "$INSTALL_DIR/settings/config/opsmon.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable opsmon.service
else
  echo "Aviso: settings/config/opsmon.service não encontrado — serviço systemd não instalado."
fi

ADMIN_PASSWORD=$(openssl rand -hex 16)
INGEST_KEY=$(openssl rand -hex 24)
echo "ADMIN_PASSWORD=$ADMIN_PASSWORD" > "$INSTALL_DIR/.admin_password"
chmod 600 "$INSTALL_DIR/.admin_password"
chown opsmon:opsmon "$INSTALL_DIR/.admin_password"

cat > "$INSTALL_DIR/.env" << EOF
# Oracle
ORACLE_HOST=localhost
ORACLE_PORT=1521
ORACLE_SERVICE_NAME=XEPDB1
ORACLE_USERNAME=opsmon
ORACLE_PASSWORD=changeme

# Redis (opcional)
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
# REDIS_PASSWORD=

# Servidor
HOST=0.0.0.0
PORT=4567
LOG_LEVEL=info

# Segurança
SESSION_SECRET=$(openssl rand -hex 32)
ADMIN_PASSWORD=$ADMIN_PASSWORD
INGEST_API_KEY=$INGEST_KEY
EOF

chmod 600 "$INSTALL_DIR/.env"
chown opsmon:opsmon "$INSTALL_DIR/.env"

if systemctl list-unit-files | grep -q '^opsmon.service'; then
  systemctl start opsmon.service || true
fi

echo ""
echo "OPSMON instalado em $INSTALL_DIR"
echo "Password admin (web): $ADMIN_PASSWORD  (também em $INSTALL_DIR/.admin_password)"
echo "INGEST_API_KEY: $INGEST_KEY  (no .env)"
echo "Ajusta ORACLE_* em $INSTALL_DIR/.env e confirma migrações (rake db:migrate)."
echo "URL: http://localhost:4567"
