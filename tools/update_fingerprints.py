"""Re-sync fingerprint rule sources and regenerate the rules files.

Sources:
  enthec/webappanalyzer  -> rules/0_wappalyzer.json  (tools/convert_wappalyzer.py)
  projectdiscovery/nuclei-templates -> rules/nuclei_tech.json (this repo,
    tools/convert_nuclei.py)

Usage:
    python tools/update_fingerprints.py [--wapp-src DIR] [--nuclei-src DIR]

If a source dir does not exist it is cloned sparse into ../ (relative to
this repo); otherwise `git pull` refreshes it. Falls back gracefully —
a failed pull keeps the existing checkout.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = [
    {
        "dir": ROOT.parent / "wappalyzer-src",
        "clone": "https://github.com/enthec/webappanalyzer.git",
        "sparse": "src/technologies src/categories.json src/schema.json",
        "src_sub": "src",
        "conv": ROOT / "tools" / "convert_wappalyzer.py",
        "out": ROOT / "rules" / "0_wappalyzer.json",
    },
    {
        "dir": ROOT.parent / "nuclei-templates",
        "clone": "https://github.com/projectdiscovery/nuclei-templates.git",
        "sparse": "http/technologies http/miscellaneous",
        "src_sub": "",
        "conv": ROOT / "tools" / "convert_nuclei.py",
        "out": ROOT / "rules" / "nuclei_tech.json",
    },
]


def sh(cmd: list, cwd=None) -> bool:
    print("+", " ".join(str(c) for c in cmd))
    return subprocess.call([str(c) for c in cmd], cwd=cwd) == 0


def sync(src: dict):
    d = src["dir"]
    if not d.exists():
        d.parent.mkdir(parents=True, exist_ok=True)
        if not sh(["git", "clone", "--depth", "1", "--filter=blob:none",
                   "--sparse", src["clone"], str(d)]):
            return False
        sh(["git", "sparse-checkout", "set", *src["sparse"].split()], cwd=d)
    else:
        if not sh(["git", "pull", "--ff-only"], cwd=d):
            print(f"! pull failed in {d}, using existing checkout")
    arg = str(d / src["src_sub"]) if src["src_sub"] else str(d)
    if not sh([sys.executable, str(src["conv"]), arg, str(src["out"])]):
        return False
    print(f"-> {src['out']}")
    return True


if __name__ == "__main__":
    ok = all(sync(s) for s in SOURCES)
    sys.exit(0 if ok else 1)
