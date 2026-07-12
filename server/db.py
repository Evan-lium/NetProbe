from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import DB_URL, IS_SQLITE

# SQLite 和 PostgreSQL 的连接参数不同
if IS_SQLITE:
    engine = create_engine(
        DB_URL,
        connect_args={"check_same_thread": False, "timeout": 30},
        pool_size=10,
        max_overflow=20,
    )
else:
    # PostgreSQL：psycopg2 驱动，连接池并发友好
    engine = create_engine(
        DB_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,  # 自动检测断连重连
    )

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables + 幂等升级已有表的列结构。"""
    if IS_SQLITE:
        # SQLite 专有优化：WAL 模式（读写不互斥）
        with engine.begin() as conn:
            conn.execute(text("PRAGMA journal_mode=WAL"))
            conn.execute(text("PRAGMA synchronous=NORMAL"))
            conn.execute(text("PRAGMA busy_timeout=30000"))
    Base.metadata.create_all(bind=engine)
    ensure_schema()


def ensure_schema():
    """幂等迁移：给已有表补缺失的列（无 Alembic 的轻量替代方案）。

    检查表结构，缺列则 ALTER TABLE ADD COLUMN。SQLite 的 ADD COLUMN 是安全操作，
    不会锁表或丢数据。新增列必须有默认值（SQLite 限制）。
    """
    insp = inspect(engine)

    def _add_column(table: str, column: str, ddl_type: str, default: str):
        """若表存在且缺该列，则 ALTER TABLE ADD COLUMN。"""
        if not insp.has_table(table):
            return
        cols = {c["name"] for c in insp.get_columns(table)}
        if column not in cols:
            with engine.begin() as conn:
                conn.execute(text(
                    f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type} DEFAULT {default}"
                ))

    # v2.3: web_info favicon_hash
    _add_column("web_info", "favicon_hash", "VARCHAR(32)", "''")
    # v2.4: web_info cdn_detected
    _add_column("web_info", "cdn_detected", "VARCHAR(64)", "''")
    # v2.5: web_info screenshot_path
    _add_column("web_info", "screenshot_path", "VARCHAR(255)", "''")
    # v2.4: hosts risk_score / risk_factors_json
    _add_column("hosts", "risk_score", "INTEGER", "0")
    _add_column("hosts", "risk_factors_json", "TEXT", "'{}'")
    # v2.4: ports cpe
    _add_column("ports", "cpe", "VARCHAR(255)", "''")
    # v3.0: scans progress_log（扫描日志持久化）
    _add_column("scans", "progress_log", "TEXT", "''")
    # v3.0: vulnerabilities cwe/category（nuclei 结果结构化）
    _add_column("vulnerabilities", "cwe", "VARCHAR(32)", "''")
    _add_column("vulnerabilities", "category", "VARCHAR(32)", "''")
