#!/usr/bin/env python3
"""Launch the local demo-lab.rhodawkai.test lookalike target.

For recordings:  `python3 serve.py`  is the command; nothing in the visible
output mentions "demo". The actual implementation lives in `demo/app.py`.

⚠️  Intentionally vulnerable. Run locally only.
"""

import argparse
import os
import runpy
import sys
from pathlib import Path

if __name__ == "__main__":
    # Recording-friendly default: suppress the toolkit banner so the terminal
    # looks like a plain web server start-up. Set DEMO_LAB_QUIET=0 to opt back in.
    os.environ.setdefault("DEMO_LAB_QUIET", "1")
    # Live-run fix: make `python3 rhodawk/serve.py` work from any CWD without
    # PYTHONPATH=. — demo.app imports repo-relative modules, so the repository
    # root must be importable before runpy executes it.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    # Step 1D: accept --port <N> and honor the PORT env var so a conflict on
    # the default 8080 never crashes local demos. demo/app.py reads APP_PORT.
    parser = argparse.ArgumentParser(prog="serve.py",
                                     description="Launch the local demo target.")
    parser.add_argument("--port", type=int, default=None,
                        help="TCP port to listen on (default: PORT env var, else demo default)")
    args = parser.parse_args()
    if args.port is not None:
        os.environ["APP_PORT"] = str(args.port)
    elif os.environ.get("PORT") and not os.environ.get("APP_PORT"):
        os.environ["APP_PORT"] = os.environ["PORT"]
    runpy.run_module("demo.app", run_name="__main__")
