import os
import sys

# Ensure project root is on sys.path so "server" resolves to this package
# regardless of whether uvicorn is launched from project root or server/
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_pkg_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from server import create_app

app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server.main:app", host="0.0.0.0", port=8000, reload=True)
