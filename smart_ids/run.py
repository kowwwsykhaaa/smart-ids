"""Start Smart IDS.

  python -m smart_ids.run                  # replay demo (safe; no admin needed)
  python -m smart_ids.run --mode live      # real capture (needs admin + Npcap/root)
  python -m smart_ids.run --mode live --enforce   # also ADD firewall block rules
"""
import argparse
import threading
import time
import webbrowser

import uvicorn

from .server import create_app


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["replay", "live"], default="replay")
    ap.add_argument("--enforce", action="store_true", help="really add firewall block rules (live mode)")
    ap.add_argument("--geo", action="store_true", help="look up IP locations via ip-api.com")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    app = create_app(a.mode, enforce_blocking=a.enforce and a.mode == "live", use_geo=a.geo)
    app.state.start()
    threading.Thread(target=lambda: (time.sleep(2), webbrowser.open(f"http://127.0.0.1:{a.port}")),
                     daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
