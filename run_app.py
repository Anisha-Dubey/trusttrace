"""TRUSTTRACE Application Launcher.

Runs the FastAPI server and automatically opens the Evidence Passport dashboard in your default browser.
"""

import os
import sys
import time
import webbrowser
import threading
from pathlib import Path

# Ensure 'src' directory is in Python module search path
ROOT = Path(__file__).resolve().parent
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
os.environ["PYTHONPATH"] = str(SRC_DIR)


def open_browser(url: str, delay: float = 1.5):
    """Wait for server to bind and launch the browser."""
    time.sleep(delay)
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"Note: Could not open browser automatically ({e}). Please navigate to {url}")


def main():
    import uvicorn
    from trusttrace.evidence.persistence.database import default_db

    # Initialize SQLite database tables on startup
    try:
        default_db.init_tables()
        print("[OK] SQLite database tables verified.")
    except Exception as e:
        print(f"[NOTE] Database init: {e}")

    host = "127.0.0.1"
    port = 8000
    app_url = f"http://{host}:{port}/"
    docs_url = f"http://{host}:{port}/docs"

    print("=" * 62)
    print("   TRUSTTRACE — Evidence-First Web Threat & Trust Triage")
    print("   HackMatrix '26 Platform")
    print("=" * 62)
    print(f"  • Interactive Dashboard: {app_url}")
    print(f"  • Swagger API Docs:      {docs_url}")
    print(f"  • ReDoc Documentation:   http://{host}:{port}/redoc")
    print(f"  • System Health Probe:   http://{host}:{port}/health")
    print("=" * 62)
    print("\nStarting Uvicorn server and opening browser...\n")

    threading.Thread(target=open_browser, args=(app_url,), daemon=True).start()

    uvicorn.run("trusttrace.api.app:app", host=host, port=port, reload=False, app_dir=str(SRC_DIR))


if __name__ == "__main__":
    main()
