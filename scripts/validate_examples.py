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

RISK_ORDER = {
    "negligible": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def load_document(path: Path) -> Any:
    """Load a JSON or YAML document."""
    with path.open("r", encoding="utf-8") as handle:
        if path.suffix.lower() == ".json":
            return json.load(handle)

        return yaml.safe_load(handle)


def format_path(parts: list[Any]) -> str:
    """Convert a schema error path to dotted notation."""
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
    """Parse a timezone-aware timestamp."""
    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        raise ValueError(
            "timestamp must include a timezone"
        )

    return parsed


def parse_amount(value: Any) -> Decimal | None:
    """Parse a decimal-string monetary amount."""
    if not isinstance(value, str):
        return None

    try:
        return Decimal(value)
    except InvalidOperation:
        return None


def all_empty_scope(
    scope: dict[str, Any],
) -> bool:
    """Return whether all executable scope arrays are empty."""
    return all(
        not scope.get(field)
        for field in SCOPE_FIELDS
    )


def review_has_decision_fields(
    review: dict[str, Any],
) -> bool:
    """Return whether a completed review has all decision fields."""
    return all(
        review.get(field) is not None
        for field in (
            "review_id",
            "reviewer_id",
            "reviewed_at",
            "rationale",
        )
    )


def policy_semantic_errors(
    document: dict[str, Any],
    decision: Any,
    review: dict[str, Any],
) -> list[str]:
    """Validate policy-result and decision consistency."""
    errors: list[str] = []

    bindings = document.get("policy_bindings")

    if not isinstance(bindings, list):
        return errors

    applied_results: list[str] = []

    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            continue

        enforcement = binding.get("enforcement")
        result = binding.get("result")
        override_ref = binding.get(
            "override_authority_ref"
        )

        if (
            enforcement == "overridden"
            and not isinstance(override_ref, str)
        ):
            errors.append(
                f"policy_bindings[{index}]."
                "override_authority_ref is required "
                "when enforcement is overridden"
            )

        if (
            enforcement != "overridden"
            and override_ref is not None
        ):
            errors.append(
                f"policy_bindings[{index}]."
                "override_authority_ref is only valid "
                "when enforcement is overridden"
            )

        if (
            enforcement == "applied"
            and isinstance(result, str)
        ):
            applied_results.append(result)

    if (
        decision in POSITIVE_DECISIONS
        and "deny" in applied_results
    ):
        errors.append(
            "positive decisions cannot retain "
            "an applied deny policy result"
        )

    if decision == "human_review_required":
        if "require_human_review" not in applied_results:
            errors.append(
                "human_review_required requires an applied "
                "require_human_review policy result"
            )

    if decision == "denied":
        if (
            "deny" not in applied_results
            and review.get("status") != "rejected"
        ):
            errors.append(
                "denied decisions require an applied "
                "deny policy result or a rejected "
                "human review"
            )

    if (
        decision in POSITIVE_DECISIONS
        and "require_human_review" in applied_results
        and review.get("status") != "approved"
    ):
        errors.append(
            "positive decisions with an applied "
            "human-review requirement need approved "
            "human review"
        )

    return errors


def human_review_semantic_errors(
    decision: Any,
    review: dict[str, Any],
) -> list[str]:
    """Validate the human-review state machine."""
    errors: list[str] = []

    required = review.get("required")
    status = review.get("status")

    decision_fields_present = (
        review_has_decision_fields(review)
    )

    if required is False:
        if status != "not_required":
            errors.append(
                "human_review.status must be "
                "not_required when required is false"
            )

        for field in (
            "review_id",
            "reviewer_id",
            "reviewed_at",
            "rationale",
        ):
            if review.get(field) is not None:
                errors.append(
                    f"human_review.{field} must be null "
                    "when review is not required"
                )

    if (
        required is True
        and status == "not_required"
    ):
        errors.append(
            "human_review.status cannot be not_required "
            "when required is true"
        )

    if status == "pending":
        if review.get("review_id") is None:
            errors.append(
                "human_review.review_id is required "
                "while review is pending"
            )

        for field in (
            "reviewer_id",
            "reviewed_at",
            "rationale",
        ):
            if review.get(field) is not None:
                errors.append(
                    f"human_review.{field} must be null "
                    "while review is pending"
                )

    if (
        status in {
            "approved",
            "rejected",
            "expired",
        }
        and not decision_fields_present
    ):
        errors.append(
            "completed human review requires review_id, "
            "reviewer_id, reviewed_at, and rationale"
        )

    if decision == "human_review_required":
        if (
            required is not True
            or status != "pending"
        ):
            errors.append(
                "human_review_required decision requires "
                "human_review.required true and "
                "status pending"
            )

    if (
        decision in POSITIVE_DECISIONS
        and status in {
            "pending",
            "rejected",
            "expired",
        }
    ):
        errors.append(
            "positive decisions cannot have pending, "
            "rejected, or expired human review"
        )

    if (
        decision == "denied"
        and status == "approved"
    ):
        errors.append(
            "denied decisions cannot have "
            "approved human review"
        )

    return errors


def risk_semantic_errors(
    decision: Any,
    review: dict[str, Any],
    assessment: dict[str, Any],
) -> list[str]:
    """Validate risk and authorization consistency."""
    errors: list[str] = []

    risk_level = assessment.get("risk_level")
    residual = assessment.get(
        "residual_risk_level"
    )

    mitigations = assessment.get(
        "mitigations",
        [],
    )

    if (
        risk_level in RISK_ORDER
        and residual in RISK_ORDER
        and RISK_ORDER[residual]
        > RISK_ORDER[risk_level]
    ):
        errors.append(
            "risk_assessment.residual_risk_level "
            "cannot exceed risk_level"
        )

    if (
        decision in POSITIVE_DECISIONS
        and residual == "critical"
    ):
        errors.append(
            "positive decisions cannot retain "
            "critical residual risk"
        )

    if (
        decision in POSITIVE_DECISIONS
        and residual == "high"
    ):
        if review.get("status") != "approved":
            errors.append(
                "high residual risk requires "
                "approved human review"
            )

        if not mitigations:
            errors.append(
                "high residual risk requires "
                "at least one mitigation"
            )

    return errors


def semantic_errors(
    document: dict[str, Any],
) -> list[str]:
    """Validate all cross-field semantic rules."""
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
            expires = parse_timestamp(
                expires_value
            )
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
        delegation_id = authority.get(
            "delegation_id"
        )

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
    review = document.get("human_review")
    assessment = document.get(
        "risk_assessment"
    )

    objects = (
        action,
        scope,
        constraints,
        review,
        assessment,
    )

    if not all(
        isinstance(value, dict)
        for value in objects
    ):
        return errors

    action_type = action.get("action_type")
    tool_id = action.get("tool_id")
    target_id = action.get("target_id")
    destination_id = action.get(
        "destination_id"
    )

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
                "requested_action.destination_id is "
                "outside constraints.allowed_destinations"
            )

        for data_class in requested_data_classes:
            if data_class not in authorized_data_classes:
                errors.append(
                    "requested_action.data_classes "
                    "contains an unauthorized data class: "
                    f"{data_class}"
                )

        if action_type in prohibited_actions:
            errors.append(
                "requested_action.action_type is listed "
                "in constraints.prohibited_actions"
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

    estimated_cost = action.get(
        "estimated_cost"
    )

    maximum_cost = constraints.get(
        "maximum_cost"
    )

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
            if (
                estimated_cost.get("currency")
                != maximum_cost.get("currency")
            ):
                errors.append(
                    "requested_action.estimated_cost "
                    "currency must match "
                    "constraints.maximum_cost currency"
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
                    "requested_action.estimated_cost "
                    "exceeds constraints.maximum_cost"
                )

    estimated_duration = action.get(
        "estimated_duration_seconds"
    )

    maximum_duration = constraints.get(
        "maximum_duration_seconds"
    )

    if (
        decision in POSITIVE_DECISIONS
        and isinstance(
            estimated_duration,
            int,
        )
        and isinstance(
            maximum_duration,
            int,
        )
        and estimated_duration > maximum_duration
    ):
        errors.append(
            "requested_action."
            "estimated_duration_seconds exceeds "
            "constraints.maximum_duration_seconds"
        )

    errors.extend(
        human_review_semantic_errors(
            decision,
            review,
        )
    )

    errors.extend(
        policy_semantic_errors(
            document,
            decision,
            review,
        )
    )

    errors.extend(
        risk_semantic_errors(
            decision,
            review,
            assessment,
        )
    )

    return errors


def example_files(
    directory: Path,
) -> list[Path]:
    """Return supported examples in deterministic order."""
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
    """Run all validation checks."""
    print(
        "=== Agent Action Authorization "
        "Receipt Protocol Validation ==="
    )

    print(
        f"schema: {SCHEMA_PATH.relative_to(ROOT)}"
    )

    try:
        schema = load_document(SCHEMA_PATH)
        Draft202012Validator.check_schema(
            schema
        )
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
