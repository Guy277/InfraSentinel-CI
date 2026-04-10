#!/usr/bin/env python3
"""
Hackathon Setup - Systeme de Protection IDS/IPS
Cree l'environnement et les fichiers necessaires pour demarrer le systeme localement.
Compatible Windows et Linux.
"""

import os
import sys
import subprocess
import shutil
import platform

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(SCRIPT_DIR, "venv")
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
DB_FILE = os.path.join(DATA_DIR, "ids.db")

IS_WINDOWS = platform.system() == "Windows"


def print_status(msg, color="GREEN"):
    colors = {
        "GREEN": "\033[0;32m",
        "YELLOW": "\033[1;33m", 
        "RED": "\033[0;31m",
        "NC": "\033[0m"
    }
    # Windows console doesn't support ANSI colors well
    if IS_WINDOWS:
        print(msg)
    else:
        print(f"{colors.get(color, '')}{msg}{colors['NC']}")


def check_requirements():
    """Verifie les paquets systeme requis."""
    print_status("Verification des dependances systeme...", "YELLOW")
    
    missing = []
    
    # Check Python
    try:
        result = subprocess.run([sys.executable, "--version"], capture_output=True, text=True)
        print(f"  Python: {result.stdout.strip()}")
    except FileNotFoundError:
        missing.append("python3")
    
    # Check pip
    try:
        result = subprocess.run(["pip3", "--version"] if not IS_WINDOWS else ["pip", "--version"], 
                              capture_output=True, text=True)
        print(f"  pip: OK")
    except FileNotFoundError:
        missing.append("pip")
    
    if IS_WINDOWS:
        print_status("  Windows detecte - Verifying Npcap...", "YELLOW")
        try:
            result = subprocess.run(["sc", "query", "npcap"], capture_output=True, text=True)
            if "RUNNING" in result.stdout:
                print_status("  Npcap: OK (installed)", "GREEN")
            else:
                print_status("  Npcap: A installer (Telecharger depuis https://npcap.com/)", "YELLOW")
        except:
            print_status("  Npcap: A installer (https://npcap.com/)", "YELLOW")
    else:
        # Check libpcap
        libpcap_paths = [
            "/usr/lib/x86_64-linux-gnu/libpcap.so",
            "/usr/lib/libpcap.so",
            "/usr/lib64/libpcap.so"
        ]
        if not any(os.path.exists(p) for p in libpcap_paths):
            print_status("  libpcap: A installer (sudo apt install libpcap-dev)", "YELLOW")
        else:
            print_status("  libpcap: OK", "GREEN")
        
        # Check iptables
        try:
            subprocess.run(["iptables", "--version"], capture_output=True, check=True)
            print_status("  iptables: OK", "GREEN")
        except (FileNotFoundError, subprocess.CalledProcessError):
            print_status("  iptables: A installer (sudo apt install iptables)", "YELLOW")
    
    if missing:
        print_status(f"Manquant: {', '.join(missing)}", "RED")
        return False
    return True


def create_venv():
    """Cree l'environnement virtuel."""
    if os.path.exists(VENV_DIR):
        print_status(f"venv deja present: {VENV_DIR}", "YELLOW")
        return True
    
    print_status("Creation de l'environnement virtuel...", "YELLOW")
    try:
        subprocess.run([sys.executable, "-m", "venv", VENV_DIR], check=True)
        print_status("Environnement virtuel cree", "GREEN")
        return True
    except Exception as e:
        print_status(f"Erreur: {e}", "RED")
        return False


def get_pip_exe():
    """Retourne le chemin de pip selon l'OS."""
    if IS_WINDOWS:
        return os.path.join(VENV_DIR, "Scripts", "pip.exe")
    return os.path.join(VENV_DIR, "bin", "pip")


def get_python_exe():
    """Retourne le chemin de python dans le venv selon l'OS."""
    if IS_WINDOWS:
        return os.path.join(VENV_DIR, "Scripts", "python.exe")
    return os.path.join(VENV_DIR, "bin", "python3")


def install_requirements():
    """Installe les dependances Python."""
    pip_exe = get_pip_exe()
    python_exe = get_python_exe()
    
    print_status("Installation des dependances Python...", "YELLOW")
    
    # Core deps only for hackathon
    deps = [
        "scapy",
        "scikit-learn",
        "pandas",
        "numpy",
        "sqlalchemy",
        "fastapi",
        "uvicorn[standard]",
        "python-multipart",
        "jinja2",
        "websockets",
        "aiofiles",
        "aiohttp",
        "python-dotenv",
    ]
    
    try:
        subprocess.run([python_exe, "-m", "pip", "install", "--upgrade", "pip"], check=True)
        for dep in deps:
            subprocess.run([pip_exe, "install", dep], check=True)
        print_status("Dependances installees", "GREEN")
        return True
    except Exception as e:
        print_status(f"Erreur installation: {e}", "RED")
        return False


def setup_directories():
    """Cree les repertoires necessaires."""
    print_status("Creation des repertoires...", "YELLOW")
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(os.path.join(SCRIPT_DIR, "logs"), exist_ok=True)
    print_status("Repertoires OK", "GREEN")


def create_env_file():
    """Cree le fichier .env pour hackathon."""
    env_path = os.path.join(SCRIPT_DIR, ".env")
    
    env_content = """# Hackathon Configuration
DB_TYPE=sqlite
DB_SQLITE_PATH=data/ids.db
DASHBOARD_PORT=9090
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=admin
LOG_LEVEL=INFO
NETWORK_INTERFACE=
"""
    
    if not os.path.exists(env_path):
        with open(env_path, "w") as f:
            f.write(env_content)
        print_status(".env cree", "GREEN")
    else:
        print_status(".env deja present", "YELLOW")


def train_model():
    """Entraine le modele IA si absent."""
    model_path = os.path.join(SCRIPT_DIR, "models", "isolation_forest.pkl")
    
    if os.path.exists(model_path):
        print_status("Modele IA deja present", "GREEN")
        return True
    
    print_status("Entrainement du modele IA...", "YELLOW")
    python = get_python_exe()
    
    try:
        # Simple training script
        code = '''
import sys
sys.path.insert(0, ".")
from ai_engine.anomaly_detector import AnomalyDetector
d = AnomalyDetector()
d.train()
print("Modele entraine avec succes")
'''
        result = subprocess.run([python, "-c", code], cwd=SCRIPT_DIR, capture_output=True, text=True)
        if result.returncode == 0:
            print_status("Modele IA pret", "GREEN")
            return True
        else:
            print_status(f"Erreur: {result.stderr}", "RED")
            return False
    except Exception as e:
        print_status(f"Erreur: {e}", "RED")
        return False


def main():
    print("=" * 60)
    print("  SYSTEME DE PROTECTION IDS/IPS - HACKATHON SETUP")
    print("=" * 60)
    print(f"  OS: {platform.system()}")
    print()
    
    # Step 1: Check system
    if not check_requirements():
        print()
        print_status("Installez les dependances manquantes et reessayez.", "RED")
        return 1
    
    # Step 2: Setup directories
    setup_directories()
    
    # Step 3: Create venv
    if not create_venv():
        return 1
    
    # Step 4: Install deps
    if not install_requirements():
        return 1
    
    # Step 5: Create .env
    create_env_file()
    
    # Step 6: Train model
    train_model()
    
    print()
    print_status("=" * 60)
    print("  SETUP COMPLET!")
    print("=" * 60)
    print()
    
    python_exe = get_python_exe()
    
    if IS_WINDOWS:
        print("Pour demarrer le systeme (Windows):")
        print(f"  {python_exe} main.py")
        print()
        print("Ou double-cliquez sur run_hackathon.bat")
        print()
        print("Dashboard: http://localhost:9090")
        print("Login: admin / admin")
        print()
        print("NOTE: Vous devez installer Npcap depuis https://npcap.com/")
    else:
        print("Pour demarrer le systeme (Linux):")
        print(f"  sudo {python_exe} main.py")
        print()
        print("Ou avec le script:")
        print("  sudo ./hackathon.sh start")
        print()
        print("Dashboard: http://localhost:9090")
        print("Login: admin / admin")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
