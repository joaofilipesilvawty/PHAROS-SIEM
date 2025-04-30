#!/bin/bash

# Exit on error
set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Check if Oracle Instant Client is installed
if [ ! -d "/usr/lib/oracle" ]; then
  echo "Oracle Instant Client not found. Please install it first."
  exit 1
fi

# Create SIEM user and group
if ! getent group siem >/dev/null; then
  groupadd siem
fi

if ! getent passwd siem >/dev/null; then
  useradd -g siem -m -s /bin/bash siem
fi

# Create installation directory
INSTALL_DIR="/opt/siem"
mkdir -p $INSTALL_DIR

# Copy files
cp -r . $INSTALL_DIR/
chown -R siem:siem $INSTALL_DIR

# Install Ruby dependencies
cd $INSTALL_DIR
su - siem -c "cd $INSTALL_DIR && bundle install --deployment"

# Create necessary directories
mkdir -p /var/log/siem
chown siem:siem /var/log/siem

# Install systemd service
cp settings/config/siem.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable siem.service

# Generate random password for admin user
ADMIN_PASSWORD=$(openssl rand -hex 16)
echo "ADMIN_PASSWORD=$ADMIN_PASSWORD" > $INSTALL_DIR/.admin_password
chmod 600 $INSTALL_DIR/.admin_password

# Create .env file
cat > $INSTALL_DIR/.env << EOF
# Database Configuration
ORACLE_HOST=localhost
ORACLE_PORT=1521
ORACLE_SERVICE_NAME=orclpdb1
ORACLE_USERNAME=siem
ORACLE_PASSWORD=siem_password

# Server Configuration
PORT=4567
LOG_LEVEL=info

# Security Configuration
SESSION_SECRET=$(openssl rand -hex 32)
ADMIN_PASSWORD=$ADMIN_PASSWORD
EOF

chmod 600 $INSTALL_DIR/.env
chown siem:siem $INSTALL_DIR/.env

# Start the service
systemctl start siem.service

echo "SIEM System installed successfully!"
echo "Admin password: $ADMIN_PASSWORD"
echo "Please change the admin password after first login."
echo "The system is running at http://localhost:4567"