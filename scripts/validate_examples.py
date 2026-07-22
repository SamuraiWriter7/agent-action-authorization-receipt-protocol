#!/usr/bin/env python3
"""Validate protocol examples against schema and semantic rules."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from decimal import Decimal, InvalidOperation
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

POSITIVE_DECISIONS = {
    "authorized",
    "conditionally_authorized",
}

BLOCKING_DECISIONS = {
    "human_review_required",
    "deferred",
    "denied",
    "revoked",
}

SCOPE_FIELDS = (
    "tools",
    "resources",
    "operations",
    "data_classes",
)


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


def parse_amount(value: Any) -> Decimal | None:
    """Parse a schema-valid decimal amount."""
    if not isinstance(value, str):
        return None

    try:
        return Decimal(value)
    except InvalidOperation:
        return None


def all_empty_scope(
    scope: dict[str, Any],
) -> bool:
    """Return whether every authorized scope array is empty."""
    return all(
        not scope.get(field)
        for field in SCOPE_FIELDS
    )


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

    decision = document.get("decision")
    action = document.get("requested_action")
    scope = document.get("authorized_scope")
    constraints = document.get("constraints")

    if not isinstance(action, dict):
        return errors

    if not isinstance(scope, dict):
        return errors

    if not isinstance(constraints, dict):
        return errors

    action_type = action.get("action_type")
    tool_id = action.get("tool_id")
    target_id = action.get("target_id")
    destination_id = action.get("destination_id")
    requested_data_classes = action.get(
        "data_classes",
        [],
    )

    tools = scope.get("tools", [])
    resources = scope.get("resources", [])
    operations = scope.get("operations", [])
    authorized_data_classes = scope.get(
        "data_classes",
        [],
    )

    prohibited_actions = constraints.get(
        "prohibited_actions",
        [],
    )

    allowed_destinations = constraints.get(
        "allowed_destinations",
        [],
    )

    execution_count = constraints.get(
        "execution_count"
    )

    if decision in POSITIVE_DECISIONS:
        if not operations:
            errors.append(
                "authorized_scope.operations must not "
                "be empty for a positive decision"
            )

        if action_type not in operations:
            errors.append(
                "requested_action.action_type is outside "
                "authorized_scope.operations"
            )

        if (
            isinstance(tool_id, str)
            and tool_id not in tools
        ):
            errors.append(
                "requested_action.tool_id is outside "
                "authorized_scope.tools"
            )

        if (
            isinstance(target_id, str)
            and target_id not in resources
        ):
            errors.append(
                "requested_action.target_id is outside "
                "authorized_scope.resources"
            )

        if (
            isinstance(destination_id, str)
            and destination_id
            not in allowed_destinations
        ):
            errors.append(
                "requested_action.destination_id is outside "
                "constraints.allowed_destinations"
            )

        for data_class in requested_data_classes:
            if data_class not in authorized_data_classes:
                errors.append(
                    "requested_action.data_classes contains "
                    "an unauthorized data class: "
                    f"{data_class}"
                )

        if action_type in prohibited_actions:
            errors.append(
                "requested_action.action_type is listed in "
                "constraints.prohibited_actions"
            )

        if (
            not isinstance(execution_count, int)
            or execution_count < 1
        ):
            errors.append(
                "constraints.execution_count must be "
                "at least 1 for a positive decision"
            )

    if decision in BLOCKING_DECISIONS:
        if not all_empty_scope(scope):
            errors.append(
                "authorized_scope must be empty "
                "for a blocking decision"
            )

        if execution_count != 0:
            errors.append(
                "constraints.execution_count must be 0 "
                "for a blocking decision"
            )

    estimated_cost = action.get("estimated_cost")
    maximum_cost = constraints.get("maximum_cost")

    if (
        decision in POSITIVE_DECISIONS
        and isinstance(estimated_cost, dict)
    ):
        if maximum_cost is None:
            estimated_amount = parse_amount(
                estimated_cost.get("amount")
            )

            if (
                estimated_amount is not None
                and estimated_amount > 0
            ):
                errors.append(
                    "a positive-cost action requires "
                    "constraints.maximum_cost"
                )

        elif isinstance(maximum_cost, dict):
            estimated_currency = estimated_cost.get(
                "currency"
            )

            maximum_currency = maximum_cost.get(
                "currency"
            )

            if estimated_currency != maximum_currency:
                errors.append(
                    "requested_action.estimated_cost currency "
                    "must match constraints.maximum_cost "
                    "currency"
                )

            estimated_amount = parse_amount(
                estimated_cost.get("amount")
            )

            maximum_amount = parse_amount(
                maximum_cost.get("amount")
            )

            if (
                estimated_amount is not None
                and maximum_amount is not None
                and estimated_amount > maximum_amount
            ):
                errors.append(
                    "requested_action.estimated_cost exceeds "
                    "constraints.maximum_cost"
                )

    estimated_duration = action.get(
        "estimated_duration_seconds"
    )

    maximum_duration = constraints.get(
        "maximum_duration_seconds"
    )

    if (
        decision in POSITIVE_DECISIONS
        and isinstance(estimated_duration, int)
        and isinstance(maximum_duration, int)
        and estimated_duration > maximum_duration
    ):
        errors.append(
            "requested_action.estimated_duration_seconds "
            "exceeds constraints.maximum_duration_seconds"
        )

    return errors


def example_files(
    directory: Path,
) -> list[Path]:
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
