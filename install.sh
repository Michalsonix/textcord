#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo ""
echo "  _______ ________   _________ _____ ____  _____  _____  "
echo " |__   __|  ____\\ \ / /__   __/ ____/ __ \|  __ \|  __ \ "
echo "    | |  | |__   \\ V /   | | | |   | |  | | |__) | |  | |"
echo "    | |  |  __|   > <    | | | |   | |  | |  _  /| |  | |"
echo "    | |  | |____ / . \\   | | | |___| |__| | | \\ \| |__| |"
echo "    |_|  |______/_/ \\_\\  |_|  \\_____\\____/|_|  \\_\\_____/ "
echo ""
echo ""
echo "  1. Install"
echo "  2. Exit"
echo ""
read -p "  Select option: " OPTION

if [ "$OPTION" != "1" ]; then
    echo "Goodbye!"
    exit 0
fi

echo ""
echo -e "${GREEN}[*] Updating repositories...${NC}"
sudo apt-get update -y

echo -e "${GREEN}[*] Installing required packages...${NC}"
sudo apt-get install -y python3 python3-pip python3-venv nginx openssl curl dnsmasq

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$INSTALL_DIR"

PORT=5000
APP_HOST="127.0.0.1"
SERVER_IP=$(hostname -I | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP="127.0.0.1"
BIND_IP="$SERVER_IP"
USE_HSTS="no"

echo -e "${GREEN}[*] Creating Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

echo -e "${GREEN}[*] Installing Python dependencies...${NC}"
pip install -r requirements.txt

echo ""
echo -e "${YELLOW}=== Administrator Account Setup ===${NC}"
read -p "  Admin identifier (login): " ADMIN_ID
read -p "  Admin first name: " ADMIN_FIRST
read -p "  Admin last name: " ADMIN_LAST
read -p "  Admin nickname (optional, press Enter to skip): " ADMIN_NICK
read -s -p "  Admin password: " ADMIN_PASS
echo ""

echo ""
read -p "  Enter domain name (e.g. textcord.local): " DOMAIN
while [ -z "$DOMAIN" ]; do
    read -p "  Domain is required. Enter domain: " DOMAIN
done

echo ""
echo "  Available network interfaces:"
ip -o link show | awk -F': ' '{print "    " NR ". " $2}'
read -p "  Select interface (or press Enter for default server IP): " IFACE_CHOICE
if [ -n "$IFACE_CHOICE" ]; then
    IFACE=$(ip -o link show | awk -F': ' "NR==$IFACE_CHOICE{print \$2}")
    IFACE_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    [ -n "$IFACE_IP" ] && BIND_IP="$IFACE_IP"
fi

echo ""
echo -e "${YELLOW}  SSL CERTIFICATE${NC}"
echo -e "${YELLOW}  [!] HSTS requires the CA certificate to be installed/trusted on clients.${NC}"
read -p "  Use HSTS? [1=Yes / 2=No]: " HSTS_OPT
[ "$HSTS_OPT" == "1" ] && USE_HSTS="yes"

create_start_script() {
    cat > "${INSTALL_DIR}/start.sh" << STARTEOF
#!/bin/bash
cd "${INSTALL_DIR}"
source venv/bin/activate
export SECRET_KEY="${SECRET_KEY}"
export TEXTCORD_HOST="${APP_HOST}"
export TEXTCORD_PORT="${PORT}"
echo "TextCord backend listening on ${APP_HOST}:${PORT}"
echo "Press Ctrl+C to stop."
python3 app.py
STARTEOF
    chmod +x "${INSTALL_DIR}/start.sh"
}

write_ssl_nginx() {
    local hsts_line=""
    if [ "$USE_HSTS" == "yes" ]; then
        hsts_line='    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;'
    fi

    # HTTPS-only: no plain HTTP service. Port 80 closed off via return 444.
    sudo tee /etc/nginx/sites-available/textcord > /dev/null << NGINXEOF
# TextCord HTTPS-only configuration
# All HTTP traffic is dropped. HSTS: ${USE_HSTS}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate ${CERT_DIR}/server.crt;
    ssl_certificate_key ${CERT_DIR}/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets on;
    ssl_buffer_size 4k;

    # Performance
    keepalive_timeout 75s;
    keepalive_requests 1000;
    client_max_body_size 50m;

    # Compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_types text/plain text/css text/javascript application/javascript application/json application/xml image/svg+xml font/woff font/woff2;

${hsts_line}

    # Static asset caching (served by Flask but cached by browser)
    location /static/ {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_cache_valid 200 1h;
        expires 7d;
        add_header Cache-Control "public, max-age=604800, immutable";
${hsts_line}
    }

    location /socket.io/ {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }

    location / {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }
}
NGINXEOF
}

apply_nginx() {
    sudo ln -sf /etc/nginx/sites-available/textcord /etc/nginx/sites-enabled/textcord
    sudo rm -f /etc/nginx/sites-enabled/default
    if sudo nginx -t 2>&1; then
        sudo systemctl restart nginx
        sudo systemctl enable nginx >/dev/null 2>&1 || true
    else
        echo -e "${RED}[!] NGINX config test failed!${NC}"
    fi
}

setup_dns() {
    echo -e "${GREEN}[*] Configuring DNS (dnsmasq)...${NC}"
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "${YELLOW}[*] Stopping systemd-resolved to free port 53...${NC}"
        sudo systemctl stop systemd-resolved
        sudo systemctl disable systemd-resolved
        sudo rm -f /etc/resolv.conf
        echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
        echo "nameserver 8.8.4.4" | sudo tee -a /etc/resolv.conf > /dev/null
    fi
    sudo tee /etc/dnsmasq.d/textcord.conf > /dev/null << DNSEOF
address=/${DOMAIN}/${BIND_IP}
listen-address=0.0.0.0
bind-interfaces
server=8.8.8.8
server=8.8.4.4
DNSEOF
    sudo systemctl restart dnsmasq
    sudo systemctl enable dnsmasq
    echo -e "${GREEN}[*] DNS configured: ${DOMAIN} -> ${BIND_IP}${NC}"
}

cat > init_db.py << PYEOF
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from app import app, db, init_db
from models import User, send_system_message

init_db()

with app.app_context():
    existing = User.query.filter_by(identifier='${ADMIN_ID}').first()
    if not existing:
        admin = User(identifier='${ADMIN_ID}', first_name='${ADMIN_FIRST}', last_name='${ADMIN_LAST}', nickname='${ADMIN_NICK}' if '${ADMIN_NICK}' else None, role='admin')
        admin.set_password('${ADMIN_PASS}')
        db.session.add(admin)
        db.session.commit()
        send_system_message(admin.id, 'Welcome ${ADMIN_FIRST} ${ADMIN_LAST}! You are the administrator. Enjoy chatting, and please be respectful!')
        print('Admin account created successfully.')
    else:
        print('Admin account already exists.')
PYEOF

echo -e "${GREEN}[*] Initializing database...${NC}"
python3 init_db.py
rm -f init_db.py

SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
create_start_script

echo -e "${GREEN}[*] Generating SSL certificate...${NC}"
CERT_DIR="${INSTALL_DIR}/certs"
mkdir -p "$CERT_DIR"
openssl genrsa -out "${CERT_DIR}/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days 3650 -key "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" -subj "/C=PL/ST=TextCord/L=TextCord/O=TextCord CA/CN=TextCord Root CA" 2>/dev/null
openssl genrsa -out "${CERT_DIR}/server.key" 2048 2>/dev/null
cat > "${CERT_DIR}/san.cnf" << SANEOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = PL
ST = TextCord
L = TextCord
O = TextCord
CN = ${DOMAIN}

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = *.${DOMAIN}
IP.1 = ${BIND_IP}
IP.2 = 127.0.0.1
SANEOF
openssl req -new -key "${CERT_DIR}/server.key" -out "${CERT_DIR}/server.csr" -config "${CERT_DIR}/san.cnf" 2>/dev/null
openssl x509 -req -days 3650 -in "${CERT_DIR}/server.csr" -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial -out "${CERT_DIR}/server.crt" -extensions v3_req -extfile "${CERT_DIR}/san.cnf" 2>/dev/null
CLIENT_CERT_PATH="${HOME}/textcord_ca_${DOMAIN}.crt"
cp "${CERT_DIR}/ca.crt" "${CLIENT_CERT_PATH}"
chmod 644 "${CLIENT_CERT_PATH}"

write_ssl_nginx
apply_nginx
setup_dns

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  TextCord installed successfully!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  Start the service:  ${YELLOW}./start.sh${NC}"
echo -e "  Access:             ${YELLOW}https://${DOMAIN}${NC}"
echo -e "  HTTP:               ${RED}blocked${NC}"
if [ "$USE_HSTS" == "yes" ]; then
    echo -e "  HSTS:               ${GREEN}enabled${NC}"
else
    echo -e "  HSTS:               ${YELLOW}disabled${NC}"
fi
echo -e "  CA Certificate:     ${YELLOW}${CLIENT_CERT_PATH}${NC}"
echo -e "  ${YELLOW}Import the CA in your browser/OS as Trusted Root CA${NC}"
echo -e "  DNS Server:         ${YELLOW}Set client DNS to ${BIND_IP}${NC}"
echo -e "  Admin panel:        ${YELLOW}/adminpage${NC}"
echo ""
