#!/usr/bin/env python3
"""Validate protocol examples against schema and semantic rules."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_PATH = (
    ROOT
    / "schemas"
    / "action-authorization-receipt.schema.json"
)

PASS_DIR = ROOT / "examples" / "pass"
FAIL_DIR = ROOT / "examples" / "fail"


def load_document(path: Path) -> Any:
    """Load a JSON or YAML document."""
    with path.open("r", encoding="utf-8") as handle:
        if path.suffix.lower() == ".json":
            return json.load(handle)

        return yaml.safe_load(handle)


def format_path(parts: list[Any]) -> str:
    """Convert a jsonschema error path to readable dotted notation."""
    if not parts:
        return "<root>"

    return ".".join(str(part) for part in parts)


def schema_errors(
    validator: Draft202012Validator,
    document: Any,
) -> list[str]:
    """Return schema errors in deterministic order."""
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: [
            str(part)
            for part in error.absolute_path
        ],
    )

    return [
        (
            f"{format_path(list(error.absolute_path))}: "
            f"{error.message}"
        )
        for error in errors
    ]


def parse_timestamp(value: str) -> datetime:
    """Parse a timezone-aware RFC 3339-style timestamp."""
    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        raise ValueError(
            "timestamp must include a timezone"
        )

    return parsed


def semantic_errors(
    document: dict[str, Any],
) -> list[str]:
    """Validate cross-field semantic rules."""
    errors: list[str] = []

    issued_value = document.get("issued_at")
    expires_value = document.get("expires_at")

    issued: datetime | None = None
    expires: datetime | None = None

    if isinstance(issued_value, str):
        try:
            issued = parse_timestamp(issued_value)
        except ValueError:
            errors.append(
                "issued_at must be a valid "
                "timezone-aware timestamp"
            )

    if isinstance(expires_value, str):
        try:
            expires = parse_timestamp(expires_value)
        except ValueError:
            errors.append(
                "expires_at must be a valid "
                "timezone-aware timestamp or null"
            )

    if (
        issued is not None
        and expires is not None
        and expires <= issued
    ):
        errors.append(
            "expires_at must be later than issued_at"
        )

    authority = document.get("authorized_by")

    if isinstance(authority, dict):
        actor_type = authority.get("actor_type")
        delegation_id = authority.get("delegation_id")

        if (
            actor_type != "delegated_agent"
            and delegation_id is not None
        ):
            errors.append(
                "authorized_by.delegation_id is only "
                "valid for delegated_agent"
            )

    return errors


def example_files(directory: Path) -> list[Path]:
    """Return supported example files in deterministic order."""
    files = list(directory.glob("*.yaml"))
    files.extend(directory.glob("*.yml"))
    files.extend(directory.glob("*.json"))

    return sorted(files)


def validate_expected_pass(
    path: Path,
    validator: Draft202012Validator,
) -> bool:
    """Validate an example that must pass."""
    print(
        f"\n[validate-pass] "
        f"{path.relative_to(ROOT)}"
    )

    try:
        document = load_document(path)
    except (
        OSError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as exc:
        print(f"[parse-error] {exc}")
        return False

    errors = schema_errors(
        validator,
        document,
    )

    if errors:
        for error in errors:
            print(f"[schema-error] {error}")

        return False

    print("[schema-ok]")

    semantic = semantic_errors(document)

    if semantic:
        for error in semantic:
            print(f"[semantic-error] {error}")

        return False

    print("[semantic-ok]")
    return True


def validate_expected_fail(
    path: Path,
    validator: Draft202012Validator,
) -> bool:
    """Validate an example that must be rejected."""
    print(
        f"\n[validate-fail] "
        f"{path.relative_to(ROOT)}"
    )

    try:
        document = load_document(path)
    except (
        OSError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as exc:
        print(
            "[rejected-as-expected] "
            f"parse error: {exc}"
        )
        return True

    errors = schema_errors(
        validator,
        document,
    )

    semantic = (
        semantic_errors(document)
        if isinstance(document, dict)
        else []
    )

    if not errors and not semantic:
        print(
            "[unexpected-pass] "
            "invalid example was accepted"
        )
        return False

    for error in errors:
        print(
            f"[expected-schema-error] {error}"
        )

    for error in semantic:
        print(
            f"[expected-semantic-error] {error}"
        )

    print("[rejected-as-expected]")
    return True


def main() -> int:
    """Run all protocol validation checks."""
    print(
        "=== Agent Action Authorization "
        "Receipt Protocol Validation ==="
    )

    print(
        f"schema: {SCHEMA_PATH.relative_to(ROOT)}"
    )

    try:
        schema = load_document(SCHEMA_PATH)
        Draft202012Validator.check_schema(schema)
    except (
        OSError,
        json.JSONDecodeError,
        yaml.YAMLError,
        SchemaError,
    ) as exc:
        print(
            "[fatal] unable to load "
            f"a valid schema: {exc}"
        )
        return 1

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    pass_files = example_files(PASS_DIR)
    fail_files = example_files(FAIL_DIR)

    if not pass_files:
        print(
            "[fatal] no passing examples found"
        )
        return 1

    if not fail_files:
        print(
            "[fatal] no failing examples found"
        )
        return 1

    results = [
        validate_expected_pass(
            path,
            validator,
        )
        for path in pass_files
    ]

    results.extend(
        validate_expected_fail(
            path,
            validator,
        )
        for path in fail_files
    )

    if all(results):
        print(
            "\nValidation completed successfully."
        )
        return 0

    print("\nValidation failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
