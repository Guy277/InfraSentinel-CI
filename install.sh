#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  IDS/IPS System - Installation Script${NC}"
echo -e "${GREEN}============================================${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Some features require root privileges${NC}"
    echo -e "${YELLOW}Run with sudo for full functionality${NC}"
fi

# Detect OS
OS="unknown"
if [ -f /etc/debian_version ]; then
    OS="debian"
    echo -e "${GREEN}Detected: Debian/Ubuntu${NC}"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    echo -e "${GREEN}Detected: RedHat/CentOS${NC}"
elif [ -f /etc/arch-release ]; then
    OS="arch"
    echo -e "${GREEN}Detected: Arch Linux${NC}"
else
    echo -e "${YELLOW}OS not detected, attempting generic installation${NC}"
fi

# Install system dependencies
echo -e "\n${GREEN}[1/6] Installing system dependencies...${NC}"
case $OS in
    debian)
        apt-get update
        apt-get install -y python3 python3-pip python3-venv postgresql postgresql-contrib \
            libpq-dev nmap tcpdump tshark iptables-persistent libpcap-dev
        ;;
    redhat)
        yum install -y python3 python3-pip postgresql-server postgresql-devel \
            nmap tcpdump wireshark-cli iptables-services libpcap-devel
        ;;
    arch)
        pacman -Sy --noconfirm python python-pip postgresql nmap tcpdump wireshark-qt iptables libpcap
        ;;
esac

# Setup PostgreSQL
echo -e "\n${GREEN}[2/6] Configuring PostgreSQL...${NC}"
if command -v systemctl &> /dev/null; then
    systemctl enable postgresql 2>/dev/null || true
    systemctl start postgresql 2>/dev/null || true
fi

# Create DB user and database
sudo -u postgres psql -c "CREATE USER ids_admin WITH PASSWORD 'secure_password';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE ids_ips OWNER ids_admin;" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ids_ips TO ids_admin;" 2>/dev/null || true

# Create Python virtual environment
echo -e "\n${GREEN}[3/6] Setting up Python environment...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

# Create required directories
echo -e "\n${GREEN}[4/6] Creating directories...${NC}"
mkdir -p logs models

# Copy environment file
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${YELLOW}Created .env file - please edit with your settings${NC}"
fi

# Initialize database
echo -e "\n${GREEN}[5/6] Initializing database...${NC}"
python database/init_db.py || echo -e "${YELLOW}Database init skipped (check DB connection)${NC}"

# Train initial model
echo -e "\n${GREEN}[6/6] Training initial AI model...${NC}"
python -c "
from ai_engine.anomaly_detector import AnomalyDetector
d = AnomalyDetector()
d.train()
print('Model trained successfully')
" || echo -e "${YELLOW}Model training deferred to first run${NC}"

# Create systemd service
echo -e "\n${GREEN}Creating systemd service...${NC}"
cat > /etc/systemd/system/ids-ips.service << EOF
[Unit]
Description=IDS/IPS Intrusion Detection and Prevention System
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${SCRIPT_DIR}/venv/bin/python ${SCRIPT_DIR}/main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload 2>/dev/null || true

echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e ""
echo -e "Start manually:"
echo -e "  ${YELLOW}cd ${SCRIPT_DIR}${NC}"
echo -e "  ${YELLOW}source venv/bin/activate${NC}"
echo -e "  ${YELLOW}sudo python main.py${NC}"
echo -e ""
echo -e "Or as service:"
echo -e "  ${YELLOW}sudo systemctl start ids-ips${NC}"
echo -e "  ${YELLOW}sudo systemctl enable ids-ips${NC}"
echo -e ""
echo -e "Dashboard: ${GREEN}http://localhost:8080${NC}"
echo -e "Credentials: ${YELLOW}admin / admin${NC}"
echo -e "${GREEN}============================================${NC}"
