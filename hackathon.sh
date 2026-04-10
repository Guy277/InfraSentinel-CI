#!/bin/bash
#
# Hackathon Launcher - Systeme de Protection IDS/IPS
# Usage: ./hackathon.sh [start|stop|status|demo|reset]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Config
DATA_DIR="$SCRIPT_DIR/data"
DB_FILE="$DATA_DIR/ids.db"
LOG_FILE="$SCRIPT_DIR/logs/ids_ips.log"

# Ensure directories exist
mkdir -p "$DATA_DIR" "$SCRIPT_DIR/logs"

show_status() {
    echo -e "${GREEN}=== Systeme de Protection IDS/IPS - Hackathon ===${NC}"
    echo ""
    echo "Database: SQLite ($DB_FILE)"
    if [ -f "$DB_FILE" ]; then
        echo "DB Size: $(du -h "$DB_FILE" | cut -f1)"
    fi
    echo "Interface: wlan0 (auto-detected)"
    echo "Dashboard: http://localhost:9090"
    echo "Login: admin / admin"
    echo ""
    
    # Check if running
    if pgrep -f "main.py" > /dev/null; then
        echo -e "${GREEN}Status: RUNNING${NC}"
        pgrep -f "main.py" | xargs -I{} ps -p {} -o cmd= | head -1
    else
        echo -e "${RED}Status: STOPPED${NC}"
    fi
}

start_demo() {
    echo -e "${YELLOW}Starting in DEMO mode (mock data)...${NC}"
    export DB_TYPE=sqlite
    export DB_SQLITE_PATH="$DB_FILE"
    export DASHBOARD_PORT=9090
    export DASHBOARD_USER=admin
    export DASHBOARD_PASSWORD=admin
    export LOG_LEVEL=INFO
    
    if [ -f "$SCRIPT_DIR/venv/bin/python3" ]; then
        sudo "$SCRIPT_DIR/venv/bin/python3" "$SCRIPT_DIR/main.py"
    else
        sudo python3 "$SCRIPT_DIR/main.py"
    fi
}

start_full() {
    echo -e "${YELLOW}Starting in FULL mode (capture + SQLite)...${NC}"
    export DB_TYPE=sqlite
    export DB_SQLITE_PATH="$DB_FILE"
    export DASHBOARD_PORT=9090
    export DASHBOARD_USER=admin
    export DASHBOARD_PASSWORD=admin
    export LOG_LEVEL=INFO
    
    if [ -f "$SCRIPT_DIR/venv/bin/python3" ]; then
        sudo "$SCRIPT_DIR/venv/bin/python3" "$SCRIPT_DIR/main.py"
    else
        sudo python3 "$SCRIPT_DIR/main.py"
    fi
}

stop_app() {
    echo "Stopping IDS/IPS..."
    pkill -f "main.py" || true
    sleep 1
    echo -e "${GREEN}Stopped.${NC}"
}

reset_db() {
    echo "Resetting database..."
    rm -f "$DB_FILE"
    rm -f "$LOG_FILE"
    rm -f "$LOG_FILE.1"
    echo -e "${GREEN}Database reset.${NC}"
}

case "${1:-status}" in
    start)
        start_full
        ;;
    demo)
        start_demo
        ;;
    stop)
        stop_app
        ;;
    status)
        show_status
        ;;
    reset)
        reset_db
        ;;
    *)
        echo "Usage: $0 {start|stop|demo|status|reset}"
        echo ""
        echo "Commands:"
        echo "  start   - Start full system (capture + SQLite)"
        echo "  demo    - Start with demo mode (mock data)"
        echo "  stop    - Stop the system"
        echo "  status  - Show system status"
        echo "  reset   - Reset database and logs"
        exit 1
        ;;
esac