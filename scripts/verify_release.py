"""Check the released file manifest; no network, simulator, or model calls."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    manifest = json.loads((ROOT / "release_manifest.json").read_text(encoding="utf-8"))
    errors = []
    for relative, item in manifest["files"].items():
        target = (ROOT / relative).resolve()
        if ROOT not in target.parents or not target.is_file():
            errors.append(f"Missing or out-of-tree file: {relative}")
            continue
        content = target.read_bytes()
        if len(content) != item["bytes"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
            errors.append(f"Content mismatch: {relative}")
    if errors:
        raise SystemExit("\n".join(errors))
    print(json.dumps({"status": "PASS", "verified_files": len(manifest["files"]), "release": manifest["release"]}))


if __name__ == "__main__":
    main()
