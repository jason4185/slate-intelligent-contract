#!/usr/bin/env python3
"""Collect only public addresses from the three named CLI accounts."""

import json
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RESULTS = Path(__file__).resolve().parent / "results"
NAMES = ("slate-owner-agent", "slate-reviewer-2", "slate-reviewer-3")


def run(*args: str) -> str:
    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    env["FORCE_COLOR"] = "0"
    result = subprocess.run(["genlayer", *args], cwd=ROOT, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
    return result.stdout


wallets = {}
for name in NAMES:
    run("account", "use", name)
    output = run("account")
    match = re.search(r"address:\s*['\"](0x[0-9a-fA-F]{40})['\"]", output)
    if not match:
        raise SystemExit(f"could not read public address for {name}")
    wallets[name] = match.group(1).lower()

if len(set(wallets.values())) != len(wallets):
    raise SystemExit("wallet addresses are not distinct")

RESULTS.mkdir(parents=True, exist_ok=True)
path = RESULTS / "wallets.json"
temporary = path.with_suffix(".json.tmp")
temporary.write_text(json.dumps(wallets, indent=2) + "\n", encoding="utf-8")
os.replace(temporary, path)
print(json.dumps(wallets, indent=2))
