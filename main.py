import logging
import sys
import signal
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config.settings import (
    LOG_FILE, LOG_LEVEL, LOG_MAX_BYTES, LOG_BACKUP_COUNT,
    DASHBOARD_HOST, DASHBOARD_PORT,
)
from database.db import init_database
from core.agent import SecurityAgent
from dashboard.app import create_app

import uvicorn


def setup_logging():
    log_dir = LOG_FILE.parent
    log_dir.mkdir(parents=True, exist_ok=True)

    from logging.handlers import RotatingFileHandler

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root_logger.addHandler(console)

    try:
        file_handler = RotatingFileHandler(
            LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except PermissionError as e:
        print(f"Warning: Cannot write to log file {LOG_FILE}: {e}")
        print("Logging to console only. Run as user (not root) for full logging.")


logger = logging.getLogger(__name__)


def main():
    setup_logging()
    logger.info("=" * 60)
    logger.info("  IDS/IPS Security Agent v1.0.0")
    logger.info("=" * 60)

    # Initialiser la base de donnees
    try:
        init_database()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Database init failed: {e}")
        logger.warning("Continuing without database persistence")

    # Creer l'agent IA
    agent = SecurityAgent()
    if not agent.initialize():
        logger.error("Agent initialization failed")
        sys.exit(1)

    # Creer la boucle asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    agent.set_event_loop(loop)

    # Gestion du signal d'arret
    def shutdown(signum, frame):
        logger.info("Shutdown signal received")
        agent.stop()
        loop.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Demarrer l'agent
    agent.start()

    # Creer et lancer le dashboard
    fastapi_app = create_app(agent)

    config = uvicorn.Config(
        fastapi_app,
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        log_level="info",
        loop="asyncio",
    )
    server = uvicorn.Server(config)

    logger.info(f"Dashboard: http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    logger.info("Credentials: admin / admin")

    try:
        loop.run_until_complete(server.serve())
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop()
        logger.info("System stopped")


if __name__ == "__main__":
    main()
