#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo ""
echo "  _______ ________   _________ _____ ____  _____  _____  "
echo " |__   __|  ____\\ \\ / /__   __/ ____/ __ \\|  __ \\|  __ \\ "
echo "    | |  | |__   \\ V /   | | | |   | |  | | |__) | |  | |"
echo "    | |  |  __|   > <    | | | |   | |  | |  _  /| |  | |"
echo "    | |  | |____ / . \\   | | | |___| |__| | | \\ \\| |__| |"
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
read -p "  Use DNS service? (required for SSL certificate) [1=Yes/2=No]: " USE_DNS

DOMAIN=""
IFACE=""
USE_SSL="no"
PORT=5000

if [ "$USE_DNS" == "1" ]; then
    read -p "  Enter domain name (e.g. example.local, example.pl): " DOMAIN
    
    echo ""
    echo "  Available network interfaces:"
    ip -o link show | awk -F': ' '{print "    " NR ". " $2}'
    read -p "  Select interface (or press Enter for all/0.0.0.0): " IFACE_CHOICE
    
    if [ -n "$IFACE_CHOICE" ]; then
        IFACE=$(ip -o link show | awk -F': ' "NR==$IFACE_CHOICE{print \$2}")
        BIND_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    fi
    [ -z "$BIND_IP" ] && BIND_IP="0.0.0.0"
    
    echo ""
    read -p "  Enable SSL encryption? [1=Yes (port 443) / 2=No (port 80)]: " USE_SSL_OPT
    
    if [ "$USE_SSL_OPT" == "1" ]; then
        USE_SSL="yes"
    fi
else
    BIND_IP="0.0.0.0"
fi

# Create initialization script
cat > init_db.py << PYEOF
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from app import app, db, init_db
from models import User, send_system_message

init_db()

with app.app_context():
    existing = User.query.filter_by(identifier='${ADMIN_ID}').first()
    if not existing:
        admin = User(
            identifier='${ADMIN_ID}',
            first_name='${ADMIN_FIRST}',
            last_name='${ADMIN_LAST}',
            nickname='${ADMIN_NICK}' if '${ADMIN_NICK}' else None,
            role='admin'
        )
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

# Generate secret key
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Create start.sh
if [ "$USE_SSL" == "yes" ] && [ -n "$DOMAIN" ]; then
    echo -e "${GREEN}[*] Configuring NGINX with SSL (self-signed)...${NC}"
    
    # ─── Generate self-signed CA and server certificate ───
    CERT_DIR="${INSTALL_DIR}/certs"
    mkdir -p "$CERT_DIR"
    
    echo -e "${GREEN}[*] Generating CA certificate...${NC}"
    openssl genrsa -out "${CERT_DIR}/ca.key" 4096 2>/dev/null
    openssl req -new -x509 -days 3650 -key "${CERT_DIR}/ca.key" \
        -out "${CERT_DIR}/ca.crt" \
        -subj "/C=PL/ST=TextCord/L=TextCord/O=TextCord CA/CN=TextCord Root CA" 2>/dev/null
    
    echo -e "${GREEN}[*] Generating server certificate for ${DOMAIN}...${NC}"
    openssl genrsa -out "${CERT_DIR}/server.key" 2048 2>/dev/null
    
    # Create SAN config for the domain + IP
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
    
    openssl req -new -key "${CERT_DIR}/server.key" \
        -out "${CERT_DIR}/server.csr" \
        -config "${CERT_DIR}/san.cnf" 2>/dev/null
    
    openssl x509 -req -days 3650 \
        -in "${CERT_DIR}/server.csr" \
        -CA "${CERT_DIR}/ca.crt" \
        -CAkey "${CERT_DIR}/ca.key" \
        -CAcreateserial \
        -out "${CERT_DIR}/server.crt" \
        -extensions v3_req \
        -extfile "${CERT_DIR}/san.cnf" 2>/dev/null
    
    # Copy CA cert to user home directory for client import
    CLIENT_CERT_PATH="${HOME}/textcord_ca_${DOMAIN}.crt"
    cp "${CERT_DIR}/ca.crt" "${CLIENT_CERT_PATH}"
    chmod 644 "${CLIENT_CERT_PATH}"
    echo -e "${GREEN}[*] Client CA certificate saved to: ${CLIENT_CERT_PATH}${NC}"
    echo -e "${YELLOW}[!] Import this certificate as Trusted Root CA in your browser/OS${NC}"
    
    sudo tee /etc/nginx/sites-available/textcord > /dev/null << NGINXEOF
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\\\$server_name\\\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate ${CERT_DIR}/server.crt;
    ssl_certificate_key ${CERT_DIR}/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \\\$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \\\$host;
        proxy_set_header X-Real-IP \\\$remote_addr;
        proxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \\\$scheme;
    }
}
NGINXEOF

    sudo ln -sf /etc/nginx/sites-available/textcord /etc/nginx/sites-enabled/
    sudo rm -f /etc/nginx/sites-enabled/default
    sudo nginx -t && sudo systemctl restart nginx
    
    # ─── Configure dnsmasq for local DNS resolution ───
    echo -e "${GREEN}[*] Configuring DNS (dnsmasq)...${NC}"
    [ -z "$BIND_IP" ] && BIND_IP=$(hostname -I | awk '{print $1}')
    
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "${YELLOW}[*] Stopping systemd-resolved to free port 53...${NC}"
        sudo systemctl stop systemd-resolved
        sudo systemctl disable systemd-resolved
        sudo rm -f /etc/resolv.conf
        echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
        echo "nameserver 8.8.4.4" | sudo tee -a /etc/resolv.conf > /dev/null
    fi
    
    sudo tee /etc/dnsmasq.d/textcord.conf > /dev/null << DNSEOF
# TextCord local DNS
address=/${DOMAIN}/${BIND_IP}
listen-address=0.0.0.0
bind-interfaces
server=8.8.8.8
server=8.8.4.4
DNSEOF
    
    sudo systemctl restart dnsmasq
    sudo systemctl enable dnsmasq
    echo -e "${GREEN}[*] DNS configured: ${DOMAIN} -> ${BIND_IP}${NC}"
    echo -e "${YELLOW}[!] Set your client DNS server to ${BIND_IP} for name resolution${NC}"
    
    cat > "${INSTALL_DIR}/start.sh" << STARTEOF
#!/bin/bash
cd "${INSTALL_DIR}"
source venv/bin/activate
export SECRET_KEY="${SECRET_KEY}"
echo "TextCord running at https://${DOMAIN}"
echo "Press Ctrl+C to stop."
python3 app.py
STARTEOF

elif [ -n "$DOMAIN" ]; then
    echo -e "${GREEN}[*] Configuring NGINX without SSL...${NC}"
    
    sudo tee /etc/nginx/sites-available/textcord > /dev/null << NGINXEOF
server {
    listen 80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \\\$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \\\$host;
        proxy_set_header X-Real-IP \\\$remote_addr;
    }
}
NGINXEOF

    sudo ln -sf /etc/nginx/sites-available/textcord /etc/nginx/sites-enabled/
    sudo rm -f /etc/nginx/sites-enabled/default
    sudo nginx -t && sudo systemctl restart nginx
    
    # ─── Configure dnsmasq for local DNS resolution ───
    echo -e "${GREEN}[*] Configuring DNS (dnsmasq)...${NC}"
    [ -z "$BIND_IP" ] && BIND_IP=$(hostname -I | awk '{print $1}')
    
    # Stop systemd-resolved if it conflicts on port 53
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "${YELLOW}[*] Stopping systemd-resolved to free port 53...${NC}"
        sudo systemctl stop systemd-resolved
        sudo systemctl disable systemd-resolved
        # Fix /etc/resolv.conf
        sudo rm -f /etc/resolv.conf
        echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
        echo "nameserver 8.8.4.4" | sudo tee -a /etc/resolv.conf > /dev/null
    fi
    
    sudo tee /etc/dnsmasq.d/textcord.conf > /dev/null << DNSEOF
# TextCord local DNS
address=/${DOMAIN}/${BIND_IP}
listen-address=0.0.0.0
bind-interfaces
server=8.8.8.8
server=8.8.4.4
DNSEOF
    
    sudo systemctl restart dnsmasq
    sudo systemctl enable dnsmasq
    echo -e "${GREEN}[*] DNS configured: ${DOMAIN} -> ${BIND_IP}${NC}"
    echo -e "${YELLOW}[!] Set your client DNS server to ${BIND_IP} for name resolution${NC}"
    
    cat > "${INSTALL_DIR}/start.sh" << STARTEOF
#!/bin/bash
cd "${INSTALL_DIR}"
source venv/bin/activate
export SECRET_KEY="${SECRET_KEY}"
echo "TextCord running at http://${DOMAIN}"
echo "Press Ctrl+C to stop."
python3 app.py
STARTEOF

else
    cat > "${INSTALL_DIR}/start.sh" << STARTEOF
#!/bin/bash
cd "${INSTALL_DIR}"
source venv/bin/activate
export SECRET_KEY="${SECRET_KEY}"
echo "TextCord running at http://${BIND_IP}:${PORT}"
echo "Press Ctrl+C to stop."
python3 app.py
STARTEOF
fi

chmod +x "${INSTALL_DIR}/start.sh"

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  TextCord installed successfully!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  Start the service:  ${YELLOW}./start.sh${NC}"
if [ -n "$DOMAIN" ]; then
    if [ "$USE_SSL" == "yes" ]; then
        echo -e "  Access:  ${YELLOW}https://${DOMAIN}${NC}"
        echo -e "  CA Certificate:  ${YELLOW}${HOME}/textcord_ca_${DOMAIN}.crt${NC}"
        echo -e "  ${YELLOW}[!] Import the CA certificate into your browser/OS as Trusted Root CA${NC}"
    else
        echo -e "  Access:  ${YELLOW}http://${DOMAIN}${NC}"
    fi
else
    echo -e "  Access:  ${YELLOW}http://${BIND_IP}:${PORT}${NC}"
fi
echo -e "  Admin panel:  ${YELLOW}/adminpage${NC}"
if [ -n "$DOMAIN" ]; then
    echo -e "  DNS Server:  ${YELLOW}Set client DNS to ${BIND_IP}${NC}"
    echo -e "  ${YELLOW}[!] Make sure firewall allows UDP/TCP port 53 (DNS)${NC}"
fi
echo ""
