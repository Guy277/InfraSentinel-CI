from database.db import init_database
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logger.info("Initializing database...")
    init_database()
    logger.info("Database initialized successfully")
