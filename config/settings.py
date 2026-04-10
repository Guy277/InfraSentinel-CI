import os
from pathlib import Path

# Load .env if available (optional for hackathon)
try:
    from dotenv import load_dotenv
    BASE_DIR = Path(__file__).resolve().parent.parent
    load_dotenv(BASE_DIR / ".env")
except ImportError:
    BASE_DIR = Path(__file__).resolve().parent.parent

# Database type: postgresql or sqlite
DB_TYPE = os.getenv("DB_TYPE", "sqlite").lower()

# Database - PostgreSQL
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_NAME = os.getenv("DB_NAME", "ids_ips")
DB_USER = os.getenv("DB_USER", "ids_admin")
DB_PASSWORD = os.getenv("DB_PASSWORD", "secure_password")

# Database - SQLite
DB_SQLITE_PATH = os.getenv("DB_SQLITE_PATH", str(BASE_DIR / "data" / "ids.db"))

# Build DATABASE_URL based on type
if DB_TYPE == "sqlite":
    os.makedirs(os.path.dirname(DB_SQLITE_PATH), exist_ok=True)
    DATABASE_URL = f"sqlite:///{DB_SQLITE_PATH}"
else:
    DATABASE_URL = os.getenv("DATABASE_URL", f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

# Capture
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "").strip()
CAPTURE_FILTER = os.getenv("CAPTURE_FILTER", "")
PACKET_BATCH_SIZE = int(os.getenv("PACKET_BATCH_SIZE", 100))
AGGREGATION_WINDOW = int(os.getenv("AGGREGATION_WINDOW", 10))

# AI Engine
MODEL_PATH = BASE_DIR / "models" / "isolation_forest.pkl"
CONTAMINATION = float(os.getenv("CONTAMINATION", 0.1))
N_ESTIMATORS = int(os.getenv("N_ESTIMATORS", 100))
TRAINING_SAMPLES = int(os.getenv("TRAINING_SAMPLES", 10000))

# Risk thresholds
RISK_LOW_MAX = float(os.getenv("RISK_LOW_MAX", 0.3))
RISK_MEDIUM_MAX = float(os.getenv("RISK_MEDIUM_MAX", 0.7))

# IPS
BLOCK_DURATION = int(os.getenv("BLOCK_DURATION", 3600))
MAX_BLOCK_DURATION = int(os.getenv("MAX_BLOCK_DURATION", 86400))
RECIDIVE_MULTIPLIER = float(os.getenv("RECIDIVE_MULTIPLIER", 2.0))
AUTO_BLOCK_CRITICAL = os.getenv("AUTO_BLOCK_CRITICAL", "true").lower() == "true"

# Alerts
SMTP_SERVER = os.getenv("SMTP_SERVER", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "admin@example.com")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

# Dashboard
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", 8081))
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-to-a-secure-random-string")
DASHBOARD_USER = os.getenv("DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "admin")

# Hybrid / Offline-first
OFFLINE_FIRST = os.getenv("OFFLINE_FIRST", "true").lower() == "true"
CONNECTIVITY_CHECK_INTERVAL = int(os.getenv("CONNECTIVITY_CHECK_INTERVAL", 30))
CONNECTIVITY_CHECK_TIMEOUT = float(os.getenv("CONNECTIVITY_CHECK_TIMEOUT", 3))
CONNECTIVITY_CHECK_URLS = [
    url.strip()
    for url in os.getenv(
        "CONNECTIVITY_CHECK_URLS",
        "http://clients3.google.com/generate_204,http://ip-api.com,https://www.google.com/generate_204",
    ).split(",")
    if url.strip()
]
HYBRID_QUEUE_PATH = os.getenv(
    "HYBRID_QUEUE_PATH",
    str(BASE_DIR / "data" / "hybrid_queue.json"),
)
ALLOW_GEO_CACHE_OFFLINE = os.getenv("ALLOW_GEO_CACHE_OFFLINE", "true").lower() == "true"

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = BASE_DIR / "logs" / "ids_ips.log"
LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", 10 * 1024 * 1024))
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", 5))

# Port Scanner
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", 300))
SCAN_TARGETS = os.getenv("SCAN_TARGETS", "192.168.1.0/24").split(",")

# Whitelist
AUTO_WHITELIST_PRIVATE = os.getenv("AUTO_WHITELIST_PRIVATE", "true").lower() == "true"
WHITELIST_IPS = [ip.strip() for ip in os.getenv("WHITELIST_IPS", "").split(",") if ip.strip()]

# Performance
MAX_PACKETS_PER_SECOND = int(os.getenv("MAX_PACKETS_PER_SECOND", 10000))
DASHBOARD_REFRESH_RATE = int(os.getenv("DASHBOARD_REFRESH_RATE", 2))

# AI Learning / Retraining
RETRAIN_ENABLED = os.getenv("RETRAIN_ENABLED", "false").lower() == "true"
RETRAIN_INTERVAL_HOURS = int(os.getenv("RETRAIN_INTERVAL_HOURS", 24))
RETRAIN_MIN_SAMPLES = int(os.getenv("RETRAIN_MIN_SAMPLES", 50))

# SignatureDetector (Snort/Suricata rules)
RULES_PATH = os.getenv("RULES_PATH", str(BASE_DIR / "rules"))

# Chatbot IA hybride (local + cloud optionnel: Gemini/Groq)
CHATBOT_ENABLED = os.getenv("CHATBOT_ENABLED", "true").lower() == "true"
CHATBOT_PROVIDER = os.getenv("CHATBOT_PROVIDER", "gemini").strip().lower()
CHATBOT_MODEL = os.getenv("CHATBOT_MODEL", "gemini-2.0-flash")
CHATBOT_LOCAL_ENABLED = os.getenv("CHATBOT_LOCAL_ENABLED", "true").lower() == "true"
CHATBOT_CLOUD_ENABLED = os.getenv("CHATBOT_CLOUD_ENABLED", "true").lower() == "true"
CHATBOT_REDACT_IPS_FOR_CLOUD = os.getenv("CHATBOT_REDACT_IPS_FOR_CLOUD", "true").lower() == "true"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Webhooks (Slack, Discord)
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
