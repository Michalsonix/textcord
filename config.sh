#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_NAME="textcord"

show_header() {
    clear
    echo ""
    echo -e "${CYAN}  _______ ________   _________ _____ ____  _____  _____  ${NC}"
    echo -e "${CYAN} |__   __|  ____\\ \\ / /__   __/ ____/ __ \\|  __ \\|  __ \\ ${NC}"
    echo -e "${CYAN}    | |  | |__   \\ V /   | | | |   | |  | | |__) | |  | |${NC}"
    echo -e "${CYAN}    | |  |  __|   > <    | | | |   | |  | |  _  /| |  | |${NC}"
    echo -e "${CYAN}    | |  | |____ / . \\   | | | |___| |__| | | \\ \\| |__| |${NC}"
    echo -e "${CYAN}    |_|  |______/_/ \\_\\  |_|  \\_____\\____/|_|  \\_\\_____/ ${NC}"
    echo ""
    echo -e "${BOLD}  Configuration Manager${NC}"
    echo ""
}

show_menu() {
    show_header
    echo -e "  ${BOLD}── Network ──${NC}"
    echo "    1. Set Static IP"
    echo "    2. Regenerate SSL Certificate"
    echo ""
    echo -e "  ${BOLD}── Service ──${NC}"
    echo "    3. Enable Autostart (systemd)"
    echo "    4. Disable Autostart (systemd)"
    echo "    5. Service Status"
    echo "    6. Restart Service"
    echo ""
    echo -e "  ${BOLD}── Administration ──${NC}"
    echo "    7. Change Admin Password"
    echo "    8. Unlock Account"
    echo "    9. Lock Account"
    echo ""
    echo -e "  ${BOLD}── Maintenance ──${NC}"
    echo "   10. Factory Reset"
    echo "    0. Exit"
    echo ""
    read -p "  Select option: " OPTION
}

set_static_ip() {
    show_header
    echo -e "${BOLD}  Set Static IP${NC}"
    echo ""
    echo "  Available interfaces:"
    ip -o link show | awk -F': ' '{print "    " NR ". " $2}'
    echo ""
    read -p "  Select interface number: " IFACE_NUM
    IFACE=$(ip -o link show | awk -F': ' "NR==$IFACE_NUM{print \$2}")
    
    if [ -z "$IFACE" ]; then
        echo -e "${RED}  Invalid interface${NC}"
        read -p "  Press Enter to continue..."
        return
    fi
    
    CURRENT_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    echo ""
    echo -e "  Current IP: ${GREEN}${CURRENT_IP:-none}${NC}"
    echo ""
    read -p "  New IP address (e.g. 192.168.1.100): " NEW_IP
    read -p "  Subnet mask (e.g. 255.255.255.0 or /24): " MASK
    read -p "  Gateway (e.g. 192.168.1.1): " GW
    
    # Convert mask if needed
    if [[ "$MASK" == "255.255.255.0" ]]; then CIDR=24
    elif [[ "$MASK" == "255.255.0.0" ]]; then CIDR=16
    elif [[ "$MASK" == "255.0.0.0" ]]; then CIDR=8
    elif [[ "$MASK" =~ ^/ ]]; then CIDR="${MASK#/}"
    else CIDR="$MASK"
    fi
    
    echo ""
    echo -e "${YELLOW}  Applying: ${NEW_IP}/${CIDR} gw ${GW} on ${IFACE}${NC}"
    
    # NetworkManager method
    if command -v nmcli &>/dev/null; then
        CON=$(nmcli -t -f NAME,DEVICE con show --active | grep ":${IFACE}$" | cut -d: -f1)
        if [ -n "$CON" ]; then
            sudo nmcli con mod "$CON" ipv4.addresses "${NEW_IP}/${CIDR}" ipv4.gateway "${GW}" ipv4.dns "8.8.8.8,8.8.4.4" ipv4.method manual
            sudo nmcli con up "$CON"
            echo -e "${GREEN}  Static IP configured via NetworkManager${NC}"
        else
            echo -e "${RED}  No active connection found on ${IFACE}${NC}"
        fi
    else
        # /etc/network/interfaces method (Debian)
        sudo tee /etc/network/interfaces.d/${IFACE}.cfg > /dev/null << NETEOF
auto ${IFACE}
iface ${IFACE} inet static
    address ${NEW_IP}
    netmask ${MASK}
    gateway ${GW}
    dns-nameservers 8.8.8.8 8.8.4.4
NETEOF
        sudo ifdown "$IFACE" 2>/dev/null
        sudo ifup "$IFACE" 2>/dev/null
        echo -e "${GREEN}  Static IP configured via /etc/network/interfaces${NC}"
    fi
    
    # Update dnsmasq if exists
    if [ -f /etc/dnsmasq.d/textcord.conf ]; then
        DOMAIN=$(grep "address=/" /etc/dnsmasq.d/textcord.conf | head -1 | cut -d/ -f2)
        if [ -n "$DOMAIN" ]; then
            sudo sed -i "s|address=/${DOMAIN}/.*|address=/${DOMAIN}/${NEW_IP}|" /etc/dnsmasq.d/textcord.conf
            sudo systemctl restart dnsmasq 2>/dev/null
            echo -e "${GREEN}  DNS updated: ${DOMAIN} -> ${NEW_IP}${NC}"
        fi
    fi
    
    read -p "  Press Enter to continue..."
}

regenerate_cert() {
    show_header
    echo -e "${BOLD}  Regenerate SSL Certificate${NC}"
    echo ""
    
    CERT_DIR="${INSTALL_DIR}/certs"
    
    # Read domain from existing config
    DOMAIN=""
    if [ -f /etc/dnsmasq.d/textcord.conf ]; then
        DOMAIN=$(grep "address=/" /etc/dnsmasq.d/textcord.conf | head -1 | cut -d/ -f2)
    fi
    
    if [ -z "$DOMAIN" ]; then
        read -p "  Enter domain name: " DOMAIN
    else
        echo -e "  Domain: ${GREEN}${DOMAIN}${NC}"
    fi
    
    BIND_IP=$(hostname -I | awk '{print $1}')
    echo -e "  Server IP: ${GREEN}${BIND_IP}${NC}"
    echo ""
    
    mkdir -p "$CERT_DIR"
    
    echo -e "${GREEN}[*] Generating new CA...${NC}"
    openssl genrsa -out "${CERT_DIR}/ca.key" 4096 2>/dev/null
    openssl req -new -x509 -days 3650 -key "${CERT_DIR}/ca.key" \
        -out "${CERT_DIR}/ca.crt" \
        -subj "/C=PL/ST=TextCord/L=TextCord/O=TextCord CA/CN=TextCord Root CA" 2>/dev/null
    
    echo -e "${GREEN}[*] Generating server certificate...${NC}"
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
    
    CLIENT_CERT_PATH="${HOME}/textcord_ca_${DOMAIN}.crt"
    cp "${CERT_DIR}/ca.crt" "${CLIENT_CERT_PATH}"
    chmod 644 "${CLIENT_CERT_PATH}"
    
    sudo nginx -t 2>/dev/null && sudo systemctl reload nginx 2>/dev/null
    
    echo ""
    echo -e "${GREEN}  Certificate regenerated successfully!${NC}"
    echo -e "  CA file: ${YELLOW}${CLIENT_CERT_PATH}${NC}"
    echo -e "${YELLOW}  Import this file in your browser/OS as Trusted Root CA${NC}"
    echo ""
    read -p "  Press Enter to continue..."
}

enable_service() {
    show_header
    echo -e "${BOLD}  Enable Autostart${NC}"
    echo ""
    
    sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << SVCEOF
[Unit]
Description=TextCord Messaging Service
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/app.py
Restart=always
RestartSec=5
Environment=SECRET_KEY=$(grep -oP "SECRET_KEY=\"\K[^\"]*" "${INSTALL_DIR}/start.sh" 2>/dev/null || echo "$(python3 -c 'import secrets;print(secrets.token_hex(32))')")

[Install]
WantedBy=multi-user.target
SVCEOF
    
    sudo systemctl daemon-reload
    sudo systemctl enable ${SERVICE_NAME}
    sudo systemctl start ${SERVICE_NAME}
    
    echo -e "${GREEN}  Service enabled and started!${NC}"
    echo -e "  Use: ${CYAN}sudo systemctl status ${SERVICE_NAME}${NC}"
    echo ""
    read -p "  Press Enter to continue..."
}

disable_service() {
    show_header
    echo -e "${BOLD}  Disable Autostart${NC}"
    echo ""
    
    sudo systemctl stop ${SERVICE_NAME} 2>/dev/null
    sudo systemctl disable ${SERVICE_NAME} 2>/dev/null
    
    echo -e "${GREEN}  Service disabled.${NC}"
    echo ""
    read -p "  Press Enter to continue..."
}

service_status() {
    show_header
    echo -e "${BOLD}  Service Status${NC}"
    echo ""
    
    # IP Info
    IP=$(hostname -I | awk '{print $1}')
    echo -e "  Server IP: ${GREEN}${IP}${NC}"
    
    # Domain
    if [ -f /etc/dnsmasq.d/textcord.conf ]; then
        DOMAIN=$(grep "address=/" /etc/dnsmasq.d/textcord.conf | head -1 | cut -d/ -f2)
        echo -e "  Domain: ${GREEN}${DOMAIN}${NC}"
    fi
    
    # Service status
    if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
        echo -e "  Service: ${GREEN}Running${NC}"
    else
        echo -e "  Service: ${RED}Stopped${NC}"
    fi
    
    # Autostart
    if systemctl is-enabled --quiet ${SERVICE_NAME} 2>/dev/null; then
        echo -e "  Autostart: ${GREEN}Enabled${NC}"
    else
        echo -e "  Autostart: ${RED}Disabled${NC}"
    fi
    
    # NGINX
    if systemctl is-active --quiet nginx 2>/dev/null; then
        echo -e "  NGINX: ${GREEN}Running${NC}"
    else
        echo -e "  NGINX: ${RED}Stopped${NC}"
    fi
    
    # DNS
    if systemctl is-active --quiet dnsmasq 2>/dev/null; then
        echo -e "  DNS (dnsmasq): ${GREEN}Running${NC}"
    else
        echo -e "  DNS (dnsmasq): ${YELLOW}Not running${NC}"
    fi
    
    # SSL
    if [ -f "${INSTALL_DIR}/certs/server.crt" ]; then
        EXPIRY=$(openssl x509 -enddate -noout -in "${INSTALL_DIR}/certs/server.crt" 2>/dev/null | cut -d= -f2)
        echo -e "  SSL Certificate: ${GREEN}Valid until ${EXPIRY}${NC}"
    else
        echo -e "  SSL Certificate: ${YELLOW}Not configured${NC}"
    fi
    
    # Recent errors
    echo ""
    echo -e "  ${BOLD}Recent Errors:${NC}"
    if systemctl is-enabled --quiet ${SERVICE_NAME} 2>/dev/null; then
        journalctl -u ${SERVICE_NAME} --no-pager -n 5 --priority=err 2>/dev/null | tail -5
        ERRCOUNT=$(journalctl -u ${SERVICE_NAME} --no-pager --priority=err --since "1 hour ago" 2>/dev/null | wc -l)
        if [ "$ERRCOUNT" -le 1 ]; then
            echo -e "  ${GREEN}No recent errors${NC}"
        fi
    else
        echo -e "  ${YELLOW}Service not registered (use option 3 first)${NC}"
    fi
    
    echo ""
    read -p "  Press Enter to continue..."
}

restart_service() {
    show_header
    echo -e "${BOLD}  Restart Service${NC}"
    echo ""
    
    if ! systemctl is-enabled --quiet ${SERVICE_NAME} 2>/dev/null; then
        echo -e "${RED}  Service is not enabled. Use option 3 first.${NC}"
        read -p "  Press Enter to continue..."
        return
    fi
    
    sudo systemctl restart ${SERVICE_NAME}
    echo -e "${GREEN}  Service restarted.${NC}"
    sleep 2
    systemctl status ${SERVICE_NAME} --no-pager -l | head -10
    echo ""
    read -p "  Press Enter to continue..."
}

change_admin_password() {
    show_header
    echo -e "${BOLD}  Change Admin Password${NC}"
    echo ""
    
    cd "$INSTALL_DIR"
    source venv/bin/activate 2>/dev/null
    
    # List admin accounts
    python3 -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from app import app, db
from models import User

with app.app_context():
    admins = User.query.filter_by(role='admin').all()
    for i, a in enumerate(admins, 1):
        print(f'    {i}. {a.first_name} {a.last_name} ({a.identifier})')
" 2>/dev/null
    
    echo ""
    read -p "  Enter admin identifier: " ADMIN_ID
    read -s -p "  New password: " NEW_PASS
    echo ""
    
    python3 -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from app import app, db
from models import User

with app.app_context():
    user = User.query.filter_by(identifier='${ADMIN_ID}', role='admin').first()
    if user:
        user.set_password('${NEW_PASS}')
        db.session.commit()
        print('  Password changed successfully!')
    else:
        print('  Admin not found!')
" 2>/dev/null
    
    echo ""
    read -p "  Press Enter to continue..."
}

manage_account() {
    local ACTION=$1
    show_header
    
    if [ "$ACTION" == "unlock" ]; then
        echo -e "${BOLD}  Unlock Account${NC}"
    else
        echo -e "${BOLD}  Lock Account${NC}"
    fi
    echo ""
    
    cd "$INSTALL_DIR"
    source venv/bin/activate 2>/dev/null
    
    # List accounts
    python3 -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from app import app, db
from models import User

with app.app_context():
    users = User.query.filter(User.identifier != 'SYSTEM').order_by(User.last_name).all()
    for i, u in enumerate(users, 1):
        status = ''
        if u.is_banned: status = ' [BANNED]'
        elif u.is_panic_locked: status = ' [LOCKED]'
        elif u.is_deleted: status = ' [DELETED]'
        print(f'    {i}. {u.first_name} {u.last_name} ({u.identifier}){status}')
" 2>/dev/null
    
    echo ""
    read -p "  Enter account identifier (or number): " TARGET
    
    python3 -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from app import app, db
from models import User

with app.app_context():
    users = User.query.filter(User.identifier != 'SYSTEM').order_by(User.last_name).all()
    target = '${TARGET}'
    user = None
    
    # Try by number
    try:
        idx = int(target) - 1
        if 0 <= idx < len(users):
            user = users[idx]
    except ValueError:
        user = User.query.filter_by(identifier=target).first()
    
    if not user:
        print('  Account not found!')
    elif '${ACTION}' == 'unlock':
        user.is_banned = False
        user.ban_reason = None
        user.ban_expires = None
        user.is_panic_locked = False
        db.session.commit()
        print(f'  Account {user.identifier} ({user.first_name} {user.last_name}) unlocked!')
    else:
        user.is_banned = True
        user.ban_reason = 'Locked via config.sh'
        user.ban_expires = None
        db.session.commit()
        print(f'  Account {user.identifier} ({user.first_name} {user.last_name}) locked!')
" 2>/dev/null
    
    echo ""
    read -p "  Press Enter to continue..."
}

factory_reset() {
    show_header
    echo -e "${RED}${BOLD}  ⚠ FACTORY RESET ⚠${NC}"
    echo ""
    echo -e "  This will:"
    echo -e "    - Delete the database"
    echo -e "    - Remove SSL certificates"
    echo -e "    - Stop and remove the systemd service"
    echo -e "    - Remove NGINX and DNS configuration"
    echo ""
    read -p "  Type 'RESET' to confirm: " CONFIRM
    
    if [ "$CONFIRM" != "RESET" ]; then
        echo -e "${YELLOW}  Cancelled.${NC}"
        read -p "  Press Enter to continue..."
        return
    fi
    
    echo ""
    echo -e "${RED}[*] Stopping services...${NC}"
    sudo systemctl stop ${SERVICE_NAME} 2>/dev/null
    sudo systemctl disable ${SERVICE_NAME} 2>/dev/null
    sudo rm -f /etc/systemd/system/${SERVICE_NAME}.service
    sudo systemctl daemon-reload
    
    echo -e "${RED}[*] Removing database...${NC}"
    rm -f "${INSTALL_DIR}/instance/textcord.db"
    
    echo -e "${RED}[*] Removing certificates...${NC}"
    rm -rf "${INSTALL_DIR}/certs"
    rm -f "${HOME}"/textcord_ca_*.crt
    
    echo -e "${RED}[*] Removing NGINX config...${NC}"
    sudo rm -f /etc/nginx/sites-enabled/textcord
    sudo rm -f /etc/nginx/sites-available/textcord
    sudo nginx -t 2>/dev/null && sudo systemctl reload nginx 2>/dev/null
    
    echo -e "${RED}[*] Removing DNS config...${NC}"
    sudo rm -f /etc/dnsmasq.d/textcord.conf
    sudo systemctl restart dnsmasq 2>/dev/null
    
    echo ""
    echo -e "${GREEN}  Factory reset complete. Run ./install.sh to set up again.${NC}"
    echo ""
    read -p "  Press Enter to exit..."
    exit 0
}

# ─── Main Loop ───
while true; do
    show_menu
    case $OPTION in
        1) set_static_ip ;;
        2) regenerate_cert ;;
        3) enable_service ;;
        4) disable_service ;;
        5) service_status ;;
        6) restart_service ;;
        7) change_admin_password ;;
        8) manage_account "unlock" ;;
        9) manage_account "lock" ;;
        10) factory_reset ;;
        0) echo "Goodbye!"; exit 0 ;;
        *) echo -e "${RED}  Invalid option${NC}"; sleep 1 ;;
    esac
done
