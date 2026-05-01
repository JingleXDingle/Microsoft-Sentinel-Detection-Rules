"""
Validates Sentinel detection rule YAMLs against the JSON schema.

Usage (from repo root or anywhere):
    python Validation_Scripts/Schema_Validation.py

Exit codes:
    0 - all files valid
    1 - one or more files failed validation (or YAML parse errors)
"""

import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft7Validator


# Paths are computed relative to this script's location so the script
# works regardless of the current working directory.
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
SCHEMA_PATH = REPO_ROOT / "Schemas" / "New_Rule_Validation_Schema.json"
DETECTIONS_DIR = REPO_ROOT / "Detections"


def load_schema(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def find_rule_files(detections_dir: Path) -> list[Path]:
    """
    Returns YAML files one level deep inside Detections/<Tactic>/.
    Does not recurse further.
    """
    rule_files = []
    for tactic_dir in sorted(detections_dir.iterdir()):
        if not tactic_dir.is_dir():
            continue
        for entry in sorted(tactic_dir.iterdir()):
            if entry.is_file() and entry.suffix.lower() in {".yaml", ".yml"}:
                rule_files.append(entry)
    return rule_files


def validate_file(path: Path, validator: Draft7Validator) -> list[str]:
    """
    Validates a single YAML file. Returns a list of error message strings.
    Empty list means the file is valid.
    """
    errors = []

    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        errors.append(f"YAML parse error: {e}")
        return errors

    if data is None:
        errors.append("File is empty or contains only comments.")
        return errors

    for err in validator.iter_errors(data):
        errors.append(str(err))

    return errors


def main() -> int:
    if not SCHEMA_PATH.is_file():
        print(f"ERROR: Schema not found at {SCHEMA_PATH}", file=sys.stderr)
        return 1

    if not DETECTIONS_DIR.is_dir():
        print(f"ERROR: Detections directory not found at {DETECTIONS_DIR}", file=sys.stderr)
        return 1

    schema = load_schema(SCHEMA_PATH)
    validator = Draft7Validator(schema)

    rule_files = find_rule_files(DETECTIONS_DIR)
    if not rule_files:
        print("No rule files found. Nothing to validate.")
        return 0

    total = len(rule_files)
    failed_files = []

    for rule_file in rule_files:
        rel_path = rule_file.relative_to(REPO_ROOT)
        errors = validate_file(rule_file, validator)

        if errors:
            failed_files.append(rel_path)
            print(f"\n=== {rel_path} ===")
            for err in errors:
                print(err)
                print()

    print("\n" + "=" * 60)
    if failed_files:
        print(f"FAILED: {len(failed_files)} of {total} rule files failed validation.")
        for f in failed_files:
            print(f"  - {f}")
        return 1
    else:
        print(f"SUCCESS: All {total} rule files valid.")
        return 0


if __name__ == "__main__":
    sys.exit(main())