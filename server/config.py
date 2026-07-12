import os
import secrets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "netprobe.db")
# 数据库 URL：设了 DATABASE_URL 用 PostgreSQL，否则回退本地 SQLite
DB_URL = os.environ.get("DATABASE_URL") or f"sqlite:///{DB_PATH}"
IS_SQLITE = DB_URL.startswith("sqlite")

# JWT 密钥：优先从环境变量读，否则用固定值（生产环境务必设置 NETPROBE_SECRET_KEY）
SECRET_KEY = os.environ.get("NETPROBE_SECRET_KEY") or "netprobe-secret-key-change-in-production"
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 7

os.makedirs(DATA_DIR, exist_ok=True)
