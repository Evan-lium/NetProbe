from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import DB_URL

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
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
    Base.metadata.create_all(bind=engine)
    ensure_schema()


def ensure_schema():
    """幂等迁移：给已有表补缺失的列（无 Alembic 的轻量替代方案）。

    检查表结构，缺列则 ALTER TABLE ADD COLUMN。SQLite 的 ADD COLUMN 是安全操作，
    不会锁表或丢数据。新增列必须有默认值（SQLite 限制）。
    """
    insp = inspect(engine)
    # web_info 表：v2.3 新增 favicon_hash 列
    if insp.has_table("web_info"):
        cols = {c["name"] for c in insp.get_columns("web_info")}
        if "favicon_hash" not in cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE web_info ADD COLUMN favicon_hash VARCHAR(32) DEFAULT ''"
                ))
