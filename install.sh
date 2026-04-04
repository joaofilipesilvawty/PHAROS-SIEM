#!/bin/bash

# Instalação em Linux (systemd) — SIEM com Oracle (JRuby + OJDBC em lib/) + Redis (opcional).
# O utilizador siem precisa de JRuby no PATH (rbenv ou pacote do sistema).

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
echo "  - Migrações: como utilizador siem, após bundle install: bundle exec rake db:migrate"
echo "  - Redis opcional (rate limit / API keys)"
echo ""

if ! getent group siem >/dev/null; then
  groupadd siem
fi

if ! getent passwd siem >/dev/null; then
  useradd -g siem -m -s /bin/bash siem
fi

INSTALL_DIR="/opt/siem"
mkdir -p "$INSTALL_DIR"

cp -r . "$INSTALL_DIR/"
chown -R siem:siem "$INSTALL_DIR"

cd "$INSTALL_DIR"

if [ -f "$INSTALL_DIR/.bundle/config" ]; then
  su - siem -s /bin/bash -c "cd $INSTALL_DIR && bundle install"
else
  su - siem -s /bin/bash -c "cd $INSTALL_DIR && bundle config set path 'vendor/bundle' && bundle install"
fi

su - siem -s /bin/bash -c "cd $INSTALL_DIR && bundle exec rake db:migrate" || {
  echo "Aviso: rake db:migrate falhou — executa manualmente após configurar Oracle."
}

mkdir -p /var/log/siem
chown siem:siem /var/log/siem

if [ -f "$INSTALL_DIR/settings/config/siem.service" ]; then
  cp "$INSTALL_DIR/settings/config/siem.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable siem.service
else
  echo "Aviso: settings/config/siem.service não encontrado — serviço systemd não instalado."
fi

ADMIN_PASSWORD=$(openssl rand -hex 16)
INGEST_KEY=$(openssl rand -hex 24)
echo "ADMIN_PASSWORD=$ADMIN_PASSWORD" > "$INSTALL_DIR/.admin_password"
chmod 600 "$INSTALL_DIR/.admin_password"
chown siem:siem "$INSTALL_DIR/.admin_password"

cat > "$INSTALL_DIR/.env" << EOF
# Oracle
ORACLE_HOST=localhost
ORACLE_PORT=1521
ORACLE_SERVICE_NAME=XEPDB1
ORACLE_USERNAME=siem
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
chown siem:siem "$INSTALL_DIR/.env"

if systemctl list-unit-files | grep -q '^siem.service'; then
  systemctl start siem.service || true
fi

echo ""
echo "SIEM instalado em $INSTALL_DIR"
echo "Password admin (web): $ADMIN_PASSWORD  (também em $INSTALL_DIR/.admin_password)"
echo "INGEST_API_KEY: $INGEST_KEY  (no .env)"
echo "Ajusta ORACLE_* em $INSTALL_DIR/.env e confirma migrações (rake db:migrate)."
echo "URL: http://localhost:4567"
