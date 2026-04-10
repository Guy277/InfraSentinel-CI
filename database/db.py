import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from config.settings import DATABASE_URL, DB_TYPE

logger = logging.getLogger(__name__)

Base = declarative_base()

# SQLite optimizations
if DB_TYPE == "sqlite":
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_raw_connection():
    """Returns raw connection. For SQLite, returns the engine's connect()."""
    if DB_TYPE == "sqlite":
        return engine.connect()
    import psycopg2
    from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASSWORD
    )


def get_dict_cursor_connection():
    """Returns (connection, cursor) for raw queries."""
    if DB_TYPE == "sqlite":
        conn = engine.connect()
        return conn, conn.exec_driver_sql
    import psycopg2
    from psycopg2.extras import RealDictCursor
    from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASSWORD
    )
    return conn, conn.cursor(cursor_factory=RealDictCursor)


def init_database():
    from database.models import Base as ModelsBase
    ModelsBase.metadata.create_all(bind=engine)
    logger.info(f"Database tables created successfully ({DB_TYPE})")