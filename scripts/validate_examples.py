#!/usr/bin/env python3
"""Validate v0.4 execution-evidence and revocation examples."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError


ROOT = Path(__file__).resolve().parents[1]

PASS = ROOT / "examples" / "pass"
FAIL = ROOT / "examples" / "fail"

SCHEMAS = {
    "receipt": (
        ROOT
        / "schemas"
        / "action-authorization-receipt.schema.json"
    ),
    "execution": (
        ROOT
        / "schemas"
        / "authorization-execution-evidence.schema.json"
    ),
    "revocation": (
        ROOT
        / "schemas"
        / "authorization-revocation-record.schema.json"
    ),
}

POSITIVE = {
    "authorized",
    "conditionally_authorized",
}


def load(path: Path) -> Any:
    """Load a JSON or YAML document."""
    with path.open("r", encoding="utf-8") as handle:
        if path.suffix == ".json":
            return json.load(handle)

        return yaml.safe_load(handle)


def files(
    directory: Path,
    prefix: str,
) -> list[Path]:
    """Return matching examples in deterministic order."""
    result: list[Path] = []

    for pattern in (
        "*.yaml",
        "*.yml",
        "*.json",
    ):
        result.extend(
            directory.glob(
                f"{prefix}{pattern}"
            )
        )

    return sorted(result)


def timestamp(
    value: Any,
) -> datetime | None:
    """Parse a timezone-aware timestamp."""
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(
            value.replace(
                "Z",
                "+00:00",
            )
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return None

    return parsed


def amount(
    value: Any,
) -> Decimal | None:
    """Parse a decimal-string monetary amount."""
    if not isinstance(value, str):
        return None

    try:
        return Decimal(value)
    except InvalidOperation:
        return None


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
            f"{'.'.join(map(str, error.absolute_path)) or '<root>'}: "
            f"{error.message}"
        )
        for error in errors
    ]


def validators(
) -> dict[str, Draft202012Validator]:
    """Load and validate all schemas."""
    result: dict[
        str,
        Draft202012Validator,
    ] = {}

    for kind, path in SCHEMAS.items():
        schema = load(path)

        Draft202012Validator.check_schema(
            schema
        )

        result[kind] = Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )

    return result


def receipt_catalog(
    validator: Draft202012Validator,
) -> dict[str, dict[str, Any]]:
    """Load passing authorization receipts."""
    result: dict[
        str,
        dict[str, Any],
    ] = {}

    for path in files(
        PASS,
        "action-authorization-receipt.",
    ):
        document = load(path)

        if not isinstance(document, dict):
            continue

        if schema_errors(
            validator,
            document,
        ):
            continue

        identifier = document.get(
            "authorization_id"
        )

        if isinstance(identifier, str):
            result[identifier] = document

    return result


def revocation_errors(
    record: dict[str, Any],
    receipts: dict[str, dict[str, Any]],
) -> list[str]:
    """Validate revocation semantics."""
    errors: list[str] = []

    authorization_id = record.get(
        "authorization_id"
    )

    if authorization_id not in receipts:
        errors.append(
            "authorization_id does not resolve "
            "to a passing receipt"
        )

    issued = timestamp(
        record.get("issued_at")
    )

    effective = timestamp(
        record.get("effective_at")
    )

    if (
        issued is not None
        and effective is not None
        and effective < issued
    ):
        errors.append(
            "effective_at must not be earlier "
            "than issued_at"
        )

    revocation_type = record.get(
        "revocation_type"
    )

    successor = record.get(
        "superseding_authorization_id"
    )

    if (
        revocation_type == "superseded"
        and not isinstance(successor, str)
    ):
        errors.append(
            "superseding_authorization_id is required "
            "when revocation_type is superseded"
        )

    if (
        revocation_type != "superseded"
        and successor is not None
    ):
        errors.append(
            "superseding_authorization_id is only valid "
            "when revocation_type is superseded"
        )

    if successor == authorization_id:
        errors.append(
            "superseding_authorization_id must differ "
            "from authorization_id"
        )

    actor = record.get("initiated_by")

    if isinstance(actor, dict):
        actor_type = actor.get(
            "actor_type"
        )

        delegation_id = actor.get(
            "delegation_id"
        )

        if (
            actor_type == "delegated_agent"
            and not delegation_id
        ):
            errors.append(
                "initiated_by.delegation_id is required "
                "for delegated_agent"
            )

        if (
            actor_type != "delegated_agent"
            and delegation_id is not None
        ):
            errors.append(
                "initiated_by.delegation_id is only valid "
                "for delegated_agent"
            )

    return errors


def revocation_catalog(
    validator: Draft202012Validator,
    receipts: dict[str, dict[str, Any]],
) -> dict[
    str,
    list[dict[str, Any]],
]:
    """Load valid passing revocation records."""
    result: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for path in files(
        PASS,
        "authorization-revocation-record.",
    ):
        record = load(path)

        if not isinstance(record, dict):
            continue

        if schema_errors(
            validator,
            record,
        ):
            continue

        if revocation_errors(
            record,
            receipts,
        ):
            continue

        authorization_id = record[
            "authorization_id"
        ]

        result[authorization_id].append(
            record
        )

    return dict(result)


def active_revocation(
    authorization_id: str,
    gate_time: datetime | None,
    revocations: dict[
        str,
        list[dict[str, Any]],
    ],
) -> dict[str, Any] | None:
    """Return the latest effective revocation."""
    if gate_time is None:
        return None

    candidates: list[
        tuple[
            datetime,
            dict[str, Any],
        ]
    ] = []

    for record in revocations.get(
        authorization_id,
        [],
    ):
        effective = timestamp(
            record.get("effective_at")
        )

        if (
            effective is not None
            and effective <= gate_time
        ):
            candidates.append(
                (
                    effective,
                    record,
                )
            )

    if not candidates:
        return None

    return max(
        candidates,
        key=lambda item: item[0],
    )[1]


def expected_codes(
    evidence: dict[str, Any],
    receipt: dict[str, Any],
    revocations: dict[
        str,
        list[dict[str, Any]],
    ],
) -> set[str]:
    """Compute authorization violations."""
    codes: set[str] = set()

    action = evidence[
        "observed_action"
    ]

    match = evidence[
        "authorization_match"
    ]

    usage = evidence[
        "execution_usage"
    ]

    requested = receipt[
        "requested_action"
    ]

    scope = receipt[
        "authorized_scope"
    ]

    constraints = receipt[
        "constraints"
    ]

    gate_time = timestamp(
        match.get("checked_at")
    )

    if receipt.get("decision") not in POSITIVE:
        codes.add(
            "decision_blocking"
        )

    expires = timestamp(
        receipt.get("expires_at")
    )

    if (
        expires is not None
        and gate_time is not None
        and gate_time >= expires
    ):
        codes.add(
            "receipt_expired"
        )

    if active_revocation(
        receipt["authorization_id"],
        gate_time,
        revocations,
    ):
        codes.add(
            "authorization_revoked"
        )

    if (
        evidence.get("request_id")
        != receipt.get("request_id")
    ):
        codes.add(
            "request_mismatch"
        )

    if (
        evidence.get("agent_id")
        != receipt.get("agent_id")
    ):
        codes.add(
            "agent_mismatch"
        )

    action_type = action.get(
        "action_type"
    )

    if (
        action_type
        not in scope.get(
            "operations",
            [],
        )
    ):
        codes.add(
            "action_type_out_of_scope"
        )

    if (
        action_type
        in constraints.get(
            "prohibited_actions",
            [],
        )
    ):
        codes.add(
            "prohibited_action"
        )

    if (
        requested.get("tool_id")
        is not None
        and action.get("tool_id")
        not in scope.get(
            "tools",
            [],
        )
    ):
        codes.add(
            "tool_out_of_scope"
        )

    if (
        requested.get("target_id")
        is not None
        and action.get("target_id")
        not in scope.get(
            "resources",
            [],
        )
    ):
        codes.add(
            "resource_out_of_scope"
        )

    if any(
        item
        not in scope.get(
            "data_classes",
            [],
        )
        for item in action.get(
            "data_classes",
            [],
        )
    ):
        codes.add(
            "data_class_out_of_scope"
        )

    if (
        requested.get("destination_id")
        is not None
        and action.get("destination_id")
        not in constraints.get(
            "allowed_destinations",
            [],
        )
    ):
        codes.add(
            "destination_out_of_scope"
        )

    actual_cost = action.get(
        "actual_cost"
    )

    maximum_cost = constraints.get(
        "maximum_cost"
    )

    if isinstance(actual_cost, dict):
        if not isinstance(
            maximum_cost,
            dict,
        ):
            actual_amount = amount(
                actual_cost.get("amount")
            )

            if (
                actual_amount is not None
                and actual_amount > 0
            ):
                codes.add(
                    "cost_limit_exceeded"
                )

        else:
            actual_amount = amount(
                actual_cost.get("amount")
            )

            maximum_amount = amount(
                maximum_cost.get("amount")
            )

            if (
                actual_cost.get("currency")
                != maximum_cost.get("currency")
            ):
                codes.add(
                    "cost_limit_exceeded"
                )

            elif (
                actual_amount is not None
                and maximum_amount is not None
                and actual_amount > maximum_amount
            ):
                codes.add(
                    "cost_limit_exceeded"
                )

    actual_duration = action.get(
        "actual_duration_seconds"
    )

    maximum_duration = constraints.get(
        "maximum_duration_seconds"
    )

    if (
        isinstance(
            actual_duration,
            int,
        )
        and isinstance(
            maximum_duration,
            int,
        )
        and actual_duration > maximum_duration
    ):
        codes.add(
            "duration_limit_exceeded"
        )

    execution_limit = constraints.get(
        "execution_count"
    )

    used_before = usage.get(
        "used_before"
    )

    if (
        isinstance(
            execution_limit,
            int,
        )
        and isinstance(
            used_before,
            int,
        )
        and used_before >= execution_limit
    ):
        codes.add(
            "execution_count_exceeded"
        )

    expected_digest = requested.get(
        "parameters_digest"
    )

    if (
        expected_digest is not None
        and action.get("parameters_digest")
        != expected_digest
    ):
        codes.add(
            "parameters_digest_mismatch"
        )

    return codes


def execution_errors(
    evidence: dict[str, Any],
    receipts: dict[str, dict[str, Any]],
    revocations: dict[
        str,
        list[dict[str, Any]],
    ],
) -> list[str]:
    """Validate execution evidence semantics."""
    receipt = receipts.get(
        evidence.get("authorization_id")
    )

    if receipt is None:
        return [
            "authorization_id does not resolve "
            "to a passing receipt"
        ]

    errors: list[str] = []

    status = evidence.get(
        "execution_status"
    )

    match = evidence[
        "authorization_match"
    ]

    usage = evidence[
        "execution_usage"
    ]

    started = timestamp(
        evidence.get("started_at")
    )

    completed = timestamp(
        evidence.get("completed_at")
    )

    checked = timestamp(
        match.get("checked_at")
    )

    recorded = timestamp(
        evidence.get("recorded_at")
    )

    if (
        status == "started"
        and (
            started is None
            or evidence.get("completed_at")
            is not None
        )
    ):
        errors.append(
            "started execution requires started_at "
            "and null completed_at"
        )

    if (
        status
        in {
            "succeeded",
            "failed",
            "cancelled",
        }
        and (
            started is None
            or completed is None
        )
    ):
        errors.append(
            f"{status} execution requires "
            "started_at and completed_at"
        )

    if (
        status == "blocked"
        and (
            evidence.get("started_at")
            is not None
            or evidence.get("completed_at")
            is not None
        )
    ):
        errors.append(
            "blocked execution requires null "
            "started_at and completed_at"
        )

    if (
        started is not None
        and completed is not None
        and completed < started
    ):
        errors.append(
            "completed_at must not be earlier "
            "than started_at"
        )

    if (
        checked is not None
        and started is not None
        and checked > started
    ):
        errors.append(
            "authorization_match.checked_at must not "
            "be later than started_at"
        )

    latest = (
        completed
        or started
        or checked
    )

    if (
        latest is not None
        and recorded is not None
        and recorded < latest
    ):
        errors.append(
            "recorded_at must not be earlier "
            "than the latest event time"
        )

    consumed = usage.get(
        "consumed"
    )

    used_before = usage.get(
        "used_before"
    )

    used_after = usage.get(
        "used_after"
    )

    sequence = usage.get(
        "sequence_number"
    )

    if consumed is True:
        if status == "blocked":
            errors.append(
                "blocked execution cannot "
                "consume authorization"
            )

        if used_after != used_before + 1:
            errors.append(
                "used_after must equal used_before + 1 "
                "when consumed is true"
            )

        if sequence != used_after:
            errors.append(
                "sequence_number must equal used_after "
                "when consumed is true"
            )

    elif consumed is False:
        if status != "blocked":
            errors.append(
                "non-blocked execution must "
                "consume authorization"
            )

        if used_after != used_before:
            errors.append(
                "used_after must equal used_before "
                "when consumed is false"
            )

        if sequence != used_before + 1:
            errors.append(
                "sequence_number must equal "
                "used_before + 1 "
                "when consumed is false"
            )

    expected = expected_codes(
        evidence,
        receipt,
        revocations,
    )

    declared = {
        item.get("code")
        for item in match.get(
            "violations",
            [],
        )
        if isinstance(item, dict)
    }

    if declared != expected:
        errors.append(
            "authorization_match.violations do not "
            "match computed violations: "
            f"expected {sorted(expected)}, "
            f"observed {sorted(declared)}"
        )

    if expected:
        if (
            match.get("status")
            != "mismatched"
        ):
            errors.append(
                "authorization_match.status must "
                "be mismatched"
            )

        if status != "blocked":
            errors.append(
                "execution_status must be blocked "
                "when violations exist"
            )

        if consumed is not False:
            errors.append(
                "violations must not consume "
                "execution count"
            )

    else:
        if (
            match.get("status")
            != "matched"
        ):
            errors.append(
                "authorization_match.status must "
                "be matched"
            )

        if match.get("violations"):
            errors.append(
                "violations must be empty when "
                "authorization matches"
            )

        if status == "blocked":
            errors.append(
                "execution_status cannot be blocked "
                "when authorization matches"
            )

    return errors


def validate(
    path: Path,
    expected_pass: bool,
    kind: str,
    validator: Draft202012Validator,
    receipts: dict[str, dict[str, Any]],
    revocations: dict[
        str,
        list[dict[str, Any]],
    ],
) -> bool:
    """Validate one expected-pass or expected-fail example."""
    expectation = (
        "pass"
        if expected_pass
        else "fail"
    )

    print(
        f"\n[validate-{expectation}] "
        f"{path.relative_to(ROOT)}"
    )

    try:
        document = load(path)
    except (
        OSError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as exc:
        if expected_pass:
            print(
                f"[parse-error] {exc}"
            )
            return False

        print(
            "[rejected-as-expected] "
            f"parse error: {exc}"
        )
        return True

    errors = schema_errors(
        validator,
        document,
    )

    semantic: list[str] = []

    if isinstance(document, dict):
        if kind == "execution":
            semantic = execution_errors(
                document,
                receipts,
                revocations,
            )

        else:
            semantic = revocation_errors(
                document,
                receipts,
            )

    if expected_pass:
        if errors:
            for error in errors:
                print(
                    f"[schema-error] {error}"
                )

            return False

        print("[schema-ok]")

        if semantic:
            for error in semantic:
                print(
                    f"[semantic-error] {error}"
                )

            return False

        print("[semantic-ok]")
        return True

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
    """Run all v0.4 validation checks."""
    print(
        "=== Authorization Execution and "
        "Revocation Validation ==="
    )

    try:
        loaded = validators()
    except (
        OSError,
        json.JSONDecodeError,
        yaml.YAMLError,
        SchemaError,
    ) as exc:
        print(
            "[fatal] unable to load "
            f"valid schemas: {exc}"
        )
        return 1

    receipts = receipt_catalog(
        loaded["receipt"]
    )

    revocations = revocation_catalog(
        loaded["revocation"],
        receipts,
    )

    results: list[bool] = []

    targets = (
        (
            "execution",
            "authorization-execution-evidence.",
        ),
        (
            "revocation",
            "authorization-revocation-record.",
        ),
    )

    for kind, prefix in targets:
        passing = files(
            PASS,
            prefix,
        )

        failing = files(
            FAIL,
            prefix,
        )

        if not passing or not failing:
            print(
                f"[fatal] {kind} requires "
                "pass and fail examples"
            )
            return 1

        results.extend(
            validate(
                path,
                True,
                kind,
                loaded[kind],
                receipts,
                revocations,
            )
            for path in passing
        )

        results.extend(
            validate(
                path,
                False,
                kind,
                loaded[kind],
                receipts,
                revocations,
            )
            for path in failing
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
