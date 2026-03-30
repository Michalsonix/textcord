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
sudo apt-get install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx curl

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
    echo -e "${GREEN}[*] Configuring NGINX with SSL...${NC}"
    
    sudo tee /etc/nginx/sites-available/textcord > /dev/null << NGINXEOF
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\\\$server_name\\\$request_uri;
}

server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

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
    
    echo -e "${YELLOW}[*] Obtaining SSL certificate...${NC}"
    sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email 2>/dev/null || {
        echo -e "${YELLOW}[!] Auto-cert failed. You may need to run: sudo certbot --nginx -d ${DOMAIN}${NC}"
    }
    
    # Copy client cert
    if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
        cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${INSTALL_DIR}/textcord_client_cert.pem"
        echo -e "${GREEN}[*] Client certificate saved to: ${INSTALL_DIR}/textcord_client_cert.pem${NC}"
    fi
    
    sudo nginx -t && sudo systemctl restart nginx
    
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
    else
        echo -e "  Access:  ${YELLOW}http://${DOMAIN}${NC}"
    fi
else
    echo -e "  Access:  ${YELLOW}http://${BIND_IP}:${PORT}${NC}"
fi
echo -e "  Admin panel:  ${YELLOW}/adminpage${NC}"
echo ""
