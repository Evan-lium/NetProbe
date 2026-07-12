#!/usr/bin/env python3
"""SQLite → PostgreSQL 数据迁移脚本。

用法:
    # 先确保 PG 已启动且 DATABASE_URL 指向目标 PG
    export DATABASE_URL=postgresql://netprobe:netprobe123@localhost:5432/netprobe
    python scripts/migrate_sqlite_to_pg.py            # 执行迁移
    python scripts/migrate_sqlite_to_pg.py --dry-run  # 预览不写入

迁移策略:
    1. 在 PG 上执行 init_db() 建表（Base.metadata.create_all）
    2. 按外键依赖顺序从 SQLite 读数据，批量写入 PG
    3. 每张表用 INSERT ... ON CONFLICT DO NOTHING（幂等，可重跑）
    4. 迁移完成后校验行数
"""
import argparse
import os
import sqlite3
import sys
from pathlib import Path

# 确保项目根目录在 sys.path
_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

SQLITE_PATH = _PROJECT_ROOT / "data" / "netprobe.db"

# 按外键依赖顺序排列（被引用的表在前）
TABLE_ORDER = [
    "scans",
    "hosts",
    "ports",
    "banners",
    "web_info",
    "whois_records",
    "vulnerabilities",
    "sensitive_paths",
    "js_findings",
    "schedules",
    "alerts",
    "alert_events",
    "scan_engines",
    "users",
    "asset_tags",
]

# SQLite 存 boolean 为 1/0 整数，PG 需要 True/False
# 列出所有 boolean 列：table → [column names]
BOOLEAN_COLUMNS = {
    "alerts": ["enabled"],
    "schedules": ["enabled"],
    "users": ["is_admin"],
}


def read_sqlite_rows(table: str, sqlite_conn: sqlite3.Connection) -> tuple[list[str], list[tuple]]:
    """从 SQLite 读一张表的列名和所有行。"""
    cursor = sqlite_conn.execute(f'SELECT * FROM "{table}"')
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    return columns, rows


def migrate(dry_run: bool = False):
    if not SQLITE_PATH.exists():
        print(f"✗ SQLite 文件不存在: {SQLITE_PATH}")
        sys.exit(1)

    # 检查 DATABASE_URL 指向 PG
    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url.startswith("postgresql"):
        print("✗ DATABASE_URL 未设置或不是 PostgreSQL")
        print("  示例: export DATABASE_URL=postgresql://netprobe:netprobe123@localhost:5432/netprobe")
        sys.exit(1)

    print(f"源: SQLite ({SQLITE_PATH})")
    print(f"目标: {db_url.split('@')[-1] if '@' in db_url else db_url}")
    print()

    # 连 SQLite
    sqlite_conn = sqlite3.connect(str(SQLITE_PATH))
    sqlite_conn.row_factory = sqlite3.Row

    # 连 PG（通过 SQLAlchemy）
    from server.db import engine, SessionLocal, init_db, Base
    from sqlalchemy import text

    print("在 PG 上建表...")
    if not dry_run:
        init_db()
    print("  ✓ 表结构已就绪")
    print()

    total_migrated = 0
    total_skipped = 0

    for table in TABLE_ORDER:
        # 检查 SQLite 里有没有这张表
        exists = sqlite_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if not exists:
            print(f"  {table:25s}  跳过（SQLite 中不存在）")
            continue

        columns, rows = read_sqlite_rows(table, sqlite_conn)
        if not rows:
            print(f"  {table:25s}  0 行（空表）")
            continue

        if dry_run:
            print(f"  {table:25s}  {len(rows):>6} 行 [dry-run]")
            total_migrated += len(rows)
            continue

        # 批量写入 PG
        # ON CONFLICT DO NOTHING：主键冲突时跳过（幂等重跑）
        col_list = ", ".join(f'"{c}"' for c in columns)
        param_list = ", ".join(f":{c}" for c in columns)
        # 用主键列做 ON CONFLICT（取第一列，通常就是主键）
        pk_col = columns[0]
        sql = text(
            f'INSERT INTO "{table}" ({col_list}) VALUES ({param_list}) '
            f'ON CONFLICT ("{pk_col}") DO NOTHING'
        )

        db = SessionLocal()
        inserted = 0
        bool_cols = BOOLEAN_COLUMNS.get(table, [])
        try:
            for row in rows:
                row_dict = {col: row[i] for i, col in enumerate(columns)}
                # SQLite boolean (1/0) → PG boolean (True/False)
                for bc in bool_cols:
                    if bc in row_dict and row_dict[bc] is not None:
                        row_dict[bc] = bool(row_dict[bc])
                result = db.execute(sql, row_dict)
                inserted += result.rowcount
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"  {table:25s}  ✗ 错误: {e}")
            continue
        finally:
            db.close()

        skipped = len(rows) - inserted
        total_migrated += inserted
        total_skipped += skipped
        status = f"{inserted:>6} 行" + (f" (跳过 {skipped} 重复)" if skipped else "")
        print(f"  {table:25s}  {status}")

    sqlite_conn.close()

    print()
    print(f"{'[dry-run] ' if dry_run else ''}迁移完成: {total_migrated} 行写入, {total_skipped} 行跳过")

    # 校验行数
    if not dry_run:
        print()
        print("行数校验:")
        db = SessionLocal()
        try:
            for table in TABLE_ORDER:
                pg_count = db.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar()
                sqlite_conn2 = sqlite3.connect(str(SQLITE_PATH))
                sqlite_count = sqlite_conn2.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                sqlite_conn2.close()
                match = "✓" if pg_count == sqlite_count else "⚠"
                print(f"  {match} {table:25s}  PG={pg_count:>6}  SQLite={sqlite_count:>6}")
        finally:
            db.close()


def main():
    parser = argparse.ArgumentParser(description="SQLite → PostgreSQL 迁移")
    parser.add_argument("--dry-run", action="store_true", help="预览不写入")
    args = parser.parse_args()
    migrate(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
