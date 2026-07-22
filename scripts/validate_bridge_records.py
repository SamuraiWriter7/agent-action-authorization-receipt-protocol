#!/usr/bin/env python3
"""Validate v0.5 protocol bridges and downstream handoffs."""

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

PASS_DIR = ROOT / "examples" / "pass"
FAIL_DIR = ROOT / "examples" / "fail"

SCHEMA_PATHS = {
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
    "bridge": (
        ROOT
        / "schemas"
        / "cross-protocol-authorization-bridge.schema.json"
    ),
    "handoff": (
        ROOT
        / "schemas"
        / "authorization-downstream-handoff.schema.json"
    ),
}

PREFIXES = {
    "receipt": "action-authorization-receipt.",
    "execution": "authorization-execution-evidence.",
    "revocation": "authorization-revocation-record.",
    "bridge": "cross-protocol-authorization-bridge.",
    "handoff": "authorization-downstream-handoff.",
}

ID_FIELDS = {
    "receipt": "authorization_id",
    "execution": "execution_evidence_id",
    "revocation": "revocation_id",
    "bridge": "bridge_id",
}

NON_EXECUTABLE_PROJECTIONS = {
    "human_challenge",
    "defer",
    "deny",
    "revoke",
}

EXECUTABLE_PROJECTIONS = {
    "allow",
    "allow_with_constraints",
}


class Catalogs:
    """Resolved passing records used for cross-record validation."""

    def __init__(
        self,
        receipts: dict[str, dict[str, Any]],
        executions: dict[str, dict[str, Any]],
        revocations: dict[str, dict[str, Any]],
        bridges: dict[str, dict[str, Any]],
    ) -> None:
        self.receipts = receipts
        self.executions = executions
        self.revocations = revocations
        self.bridges = bridges


def load_document(path: Path) -> Any:
    """Load a JSON or YAML document."""
    with path.open("r", encoding="utf-8") as handle:
        if path.suffix.lower() == ".json":
            return json.load(handle)

        return yaml.safe_load(handle)


def parse_timestamp(value: Any) -> datetime | None:
    """Parse a timezone-aware timestamp."""
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return None

    return parsed


def format_path(parts: list[Any]) -> str:
    """Convert a schema path to dotted notation."""
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


def matching_files(
    directory: Path,
    prefix: str,
) -> list[Path]:
    """Return matching example files in deterministic order."""
    files: list[Path] = []

    for pattern in (
        "*.yaml",
        "*.yml",
        "*.json",
    ):
        files.extend(
            directory.glob(
                f"{prefix}{pattern}"
            )
        )

    return sorted(files)


def load_validators() -> dict[str, Draft202012Validator]:
    """Load and validate all schemas."""
    validators: dict[str, Draft202012Validator] = {}

    for kind, path in SCHEMA_PATHS.items():
        schema = load_document(path)

        Draft202012Validator.check_schema(
            schema
        )

        validators[kind] = Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )

    return validators


def load_catalog(
    kind: str,
    validator: Draft202012Validator,
) -> dict[str, dict[str, Any]]:
    """Load schema-valid passing records into a catalog."""
    result: dict[str, dict[str, Any]] = {}

    for path in matching_files(
        PASS_DIR,
        PREFIXES[kind],
    ):
        document = load_document(path)

        if not isinstance(document, dict):
            continue

        if schema_errors(
            validator,
            document,
        ):
            continue

        identifier = document.get(
            ID_FIELDS[kind]
        )

        if isinstance(identifier, str):
            result[identifier] = document

    return result


def active_revocation(
    authorization_id: str,
    bound_at: datetime | None,
    revocations: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Return the latest effective revocation."""
    if bound_at is None:
        return None

    candidates: list[
        tuple[datetime, dict[str, Any]]
    ] = []

    for record in revocations.values():
        if (
            record.get("authorization_id")
            != authorization_id
        ):
            continue

        effective_at = parse_timestamp(
            record.get("effective_at")
        )

        if (
            effective_at is not None
            and effective_at <= bound_at
        ):
            candidates.append(
                (
                    effective_at,
                    record,
                )
            )

    if not candidates:
        return None

    return max(
        candidates,
        key=lambda item: item[0],
    )[1]


def expected_projection(
    receipt: dict[str, Any],
    bound_at: datetime | None,
    revocations: dict[str, dict[str, Any]],
) -> str:
    """Compute the protocol-facing authorization decision."""
    authorization_id = receipt.get(
        "authorization_id"
    )

    if (
        isinstance(authorization_id, str)
        and active_revocation(
            authorization_id,
            bound_at,
            revocations,
        )
        is not None
    ):
        return "revoke"

    expires_at = parse_timestamp(
        receipt.get("expires_at")
    )

    if (
        expires_at is not None
        and bound_at is not None
        and bound_at >= expires_at
    ):
        return "revoke"

    mapping = {
        "authorized": "allow",
        "conditionally_authorized": (
            "allow_with_constraints"
        ),
        "human_review_required": (
            "human_challenge"
        ),
        "deferred": "defer",
        "denied": "deny",
        "revoked": "revoke",
    }

    return mapping.get(
        receipt.get("decision"),
        "deny",
    )


def protocol_binding_errors(
    binding: dict[str, Any],
) -> list[str]:
    """Validate protocol-specific binding invariants."""
    errors: list[str] = []

    protocol = binding.get("protocol")

    capability_id = binding.get(
        "capability_id"
    )

    resource_indicator = binding.get(
        "resource_indicator"
    )

    agent_card_reference = binding.get(
        "agent_card_reference"
    )

    http_method = binding.get(
        "http_method"
    )

    extension_reference = binding.get(
        "extension_reference"
    )

    security_scheme_refs = binding.get(
        "security_scheme_refs",
        [],
    )

    required_scopes = binding.get(
        "required_scopes",
        [],
    )

    authentication = binding.get(
        "authentication",
        {},
    )

    if not isinstance(authentication, dict):
        return errors

    scheme = authentication.get("scheme")

    credential_reference = authentication.get(
        "credential_reference"
    )

    requested_scopes = authentication.get(
        "requested_scopes",
        [],
    )

    audience = authentication.get("audience")
    issuer = authentication.get("issuer")

    missing_scopes = sorted(
        set(required_scopes)
        - set(requested_scopes)
    )

    if missing_scopes:
        errors.append(
            "protocol_binding.required_scopes are not "
            "covered by authentication.requested_scopes: "
            f"{missing_scopes}"
        )

    if scheme == "none":
        if credential_reference is not None:
            errors.append(
                "authentication.credential_reference "
                "must be null when scheme is none"
            )

        if requested_scopes:
            errors.append(
                "authentication.requested_scopes "
                "must be empty when scheme is none"
            )

        if (
            audience is not None
            or issuer is not None
        ):
            errors.append(
                "authentication.audience and issuer "
                "must be null when scheme is none"
            )

        if security_scheme_refs:
            errors.append(
                "protocol_binding.security_scheme_refs "
                "must be empty when authentication "
                "scheme is none"
            )

    elif credential_reference is None:
        errors.append(
            "authentication.credential_reference "
            "is required for authenticated "
            "protocol bindings"
        )

    if required_scopes and scheme == "none":
        errors.append(
            "required scopes cannot be used with "
            "authentication scheme none"
        )

    if protocol == "mcp":
        if resource_indicator is None:
            errors.append(
                "MCP binding requires "
                "resource_indicator"
            )

        if (
            resource_indicator
            != binding.get("endpoint")
        ):
            errors.append(
                "MCP resource_indicator "
                "must equal endpoint"
            )

        if (
            audience is not None
            and audience != resource_indicator
        ):
            errors.append(
                "MCP authentication.audience "
                "must equal resource_indicator"
            )

        if any(
            value is not None
            for value in (
                agent_card_reference,
                http_method,
                extension_reference,
            )
        ):
            errors.append(
                "MCP binding cannot use Agent Card, "
                "HTTP method, or custom extension fields"
            )

    elif protocol == "a2a":
        if agent_card_reference is None:
            errors.append(
                "A2A binding requires "
                "agent_card_reference"
            )

        if capability_id is None:
            errors.append(
                "A2A binding requires "
                "capability_id"
            )

        if any(
            value is not None
            for value in (
                resource_indicator,
                http_method,
                extension_reference,
            )
        ):
            errors.append(
                "A2A binding cannot use MCP resource, "
                "HTTP method, or custom extension fields"
            )

        if (
            scheme != "none"
            and not security_scheme_refs
        ):
            errors.append(
                "authenticated A2A binding requires "
                "security_scheme_refs"
            )

    elif protocol == "http_api":
        if http_method is None:
            errors.append(
                "HTTP API binding requires "
                "http_method"
            )

        if any(
            value is not None
            for value in (
                resource_indicator,
                agent_card_reference,
                extension_reference,
            )
        ):
            errors.append(
                "HTTP API binding cannot use "
                "MCP resource, Agent Card, "
                "or custom extension fields"
            )

    elif protocol == "local_agent":
        if capability_id is None:
            errors.append(
                "local agent binding requires "
                "capability_id"
            )

        if any(
            value is not None
            for value in (
                resource_indicator,
                agent_card_reference,
                http_method,
                extension_reference,
            )
        ):
            errors.append(
                "local agent binding cannot use "
                "remote protocol fields"
            )

    elif protocol == "custom":
        if extension_reference is None:
            errors.append(
                "custom binding requires "
                "extension_reference"
            )

        if any(
            value is not None
            for value in (
                resource_indicator,
                agent_card_reference,
                http_method,
            )
        ):
            errors.append(
                "custom binding cannot use reserved "
                "MCP, A2A, or HTTP fields"
            )

    return errors


def bridge_semantic_errors(
    bridge: dict[str, Any],
    catalogs: Catalogs,
) -> list[str]:
    """Validate bridge and source-record consistency."""
    errors: list[str] = []

    authorization_id = bridge.get(
        "authorization_id"
    )

    receipt = catalogs.receipts.get(
        authorization_id
    )

    if receipt is None:
        return [
            "authorization_id does not resolve "
            "to a passing receipt"
        ]

    projection = bridge.get(
        "authorization_projection"
    )

    binding = bridge.get(
        "protocol_binding"
    )

    transport = bridge.get(
        "transport_evidence"
    )

    if not all(
        isinstance(value, dict)
        for value in (
            projection,
            binding,
            transport,
        )
    ):
        return errors

    bound_at = parse_timestamp(
        transport.get("bound_at")
    )

    created_at = parse_timestamp(
        bridge.get("created_at")
    )

    if (
        bound_at is not None
        and created_at is not None
        and created_at < bound_at
    ):
        errors.append(
            "created_at must not be earlier than "
            "transport_evidence.bound_at"
        )

    expected = expected_projection(
        receipt,
        bound_at,
        catalogs.revocations,
    )

    if (
        projection.get("projected_decision")
        != expected
    ):
        errors.append(
            "authorization_projection."
            "projected_decision must be "
            f"{expected}"
        )

    requested_action = receipt.get(
        "requested_action",
        {},
    )

    direct_comparisons = {
        "source_decision": receipt.get(
            "decision"
        ),
        "request_id": receipt.get(
            "request_id"
        ),
        "agent_id": receipt.get(
            "agent_id"
        ),
        "action_type": requested_action.get(
            "action_type"
        ),
        "scope_snapshot": receipt.get(
            "authorized_scope"
        ),
        "constraint_snapshot": receipt.get(
            "constraints"
        ),
        "parameters_digest": requested_action.get(
            "parameters_digest"
        ),
        "expires_at": receipt.get(
            "expires_at"
        ),
    }

    for field, expected_value in (
        direct_comparisons.items()
    ):
        if projection.get(field) != expected_value:
            errors.append(
                f"authorization_projection.{field} "
                "does not match the source receipt"
            )

    errors.extend(
        protocol_binding_errors(binding)
    )

    projected_decision = projection.get(
        "projected_decision"
    )

    transport_status = transport.get(
        "status"
    )

    execution_ids = bridge.get(
        "execution_evidence_ids",
        [],
    )

    if (
        projected_decision
        in NON_EXECUTABLE_PROJECTIONS
        and transport_status != "blocked"
    ):
        errors.append(
            "non-executable projections require "
            "transport_evidence.status blocked"
        )

    if transport_status == "completed":
        for field in (
            "request_digest",
            "response_digest",
            "response_code",
        ):
            if transport.get(field) is None:
                errors.append(
                    f"transport_evidence.{field} "
                    "is required when status "
                    "is completed"
                )

        if (
            projected_decision
            in EXECUTABLE_PROJECTIONS
            and not execution_ids
        ):
            errors.append(
                "completed executable bridge requires "
                "at least one execution_evidence_id"
            )

    if transport_status == "prepared":
        if any(
            transport.get(field) is not None
            for field in (
                "response_digest",
                "response_code",
            )
        ):
            errors.append(
                "prepared transport cannot contain "
                "response evidence"
            )

        if execution_ids:
            errors.append(
                "prepared transport cannot link "
                "execution evidence"
            )

    for execution_id in execution_ids:
        execution = catalogs.executions.get(
            execution_id
        )

        if execution is None:
            errors.append(
                "execution_evidence_id "
                "does not resolve: "
                f"{execution_id}"
            )
            continue

        if (
            execution.get("authorization_id")
            != authorization_id
        ):
            errors.append(
                f"{execution_id} belongs to "
                "a different authorization"
            )

        if (
            execution.get("request_id")
            != receipt.get("request_id")
        ):
            errors.append(
                f"{execution_id} request_id "
                "does not match receipt"
            )

        if (
            execution.get("agent_id")
            != receipt.get("agent_id")
        ):
            errors.append(
                f"{execution_id} agent_id "
                "does not match receipt"
            )

        execution_status = execution.get(
            "execution_status"
        )

        if (
            projected_decision
            in NON_EXECUTABLE_PROJECTIONS
            and execution_status != "blocked"
        ):
            errors.append(
                f"{execution_id} must be blocked "
                "for a non-executable projection"
            )

    return errors


def handoff_semantic_errors(
    handoff: dict[str, Any],
    catalogs: Catalogs,
) -> list[str]:
    """Validate downstream ordering and settlement gates."""
    errors: list[str] = []

    bridge_id = handoff.get("bridge_id")

    bridge = catalogs.bridges.get(
        bridge_id
    )

    if bridge is None:
        return [
            "bridge_id does not resolve "
            "to a passing bridge"
        ]

    if (
        handoff.get("authorization_id")
        != bridge.get("authorization_id")
    ):
        errors.append(
            "authorization_id does not "
            "match the bridge"
        )

    handoff_execution_ids = set(
        handoff.get(
            "execution_evidence_ids",
            [],
        )
    )

    bridge_execution_ids = set(
        bridge.get(
            "execution_evidence_ids",
            [],
        )
    )

    if (
        handoff_execution_ids
        != bridge_execution_ids
    ):
        errors.append(
            "execution_evidence_ids must "
            "exactly match the bridge"
        )

    emitted_at = parse_timestamp(
        handoff.get("emitted_at")
    )

    bridge_created_at = parse_timestamp(
        bridge.get("created_at")
    )

    if (
        emitted_at is not None
        and bridge_created_at is not None
        and emitted_at < bridge_created_at
    ):
        errors.append(
            "emitted_at must not be earlier "
            "than bridge.created_at"
        )

    destinations = handoff.get(
        "destinations"
    )

    gate = handoff.get(
        "settlement_gate"
    )

    if (
        not isinstance(destinations, dict)
        or not isinstance(gate, dict)
    ):
        return errors

    for name, destination in (
        destinations.items()
    ):
        if not isinstance(destination, dict):
            continue

        status = destination.get("status")

        refs = destination.get(
            "record_refs",
            [],
        )

        if (
            status == "not_applicable"
            and refs
        ):
            errors.append(
                f"destinations.{name}.record_refs "
                "must be empty when status "
                "is not_applicable"
            )

        if (
            status in {
                "ready",
                "completed",
            }
            and not refs
        ):
            errors.append(
                f"destinations.{name}.record_refs "
                f"must not be empty when status "
                f"is {status}"
            )

    audit = destinations.get("audit", {})
    dispute = destinations.get("dispute", {})

    responsibility = destinations.get(
        "responsibility",
        {},
    )

    royalty = destinations.get(
        "royalty",
        {},
    )

    audit_status = audit.get("status")
    dispute_status = dispute.get("status")

    responsibility_status = (
        responsibility.get("status")
    )

    royalty_status = royalty.get("status")

    gate_status = gate.get("status")

    reason_code = gate.get(
        "reason_code"
    )

    unresolved = gate.get(
        "unresolved_dispute_refs",
        [],
    )

    if gate_status == "released":
        if reason_code is not None:
            errors.append(
                "released settlement gate "
                "requires null reason_code"
            )

        if unresolved:
            errors.append(
                "released settlement gate "
                "cannot retain unresolved disputes"
            )

        if dispute_status in {
            "pending",
            "ready",
            "held",
            "blocked",
        }:
            errors.append(
                "released settlement gate requires "
                "dispute completion or "
                "non-applicability"
            )

    if gate_status in {
        "held",
        "blocked",
    }:
        if reason_code is None:
            errors.append(
                "held or blocked settlement gate "
                "requires reason_code"
            )

    if unresolved:
        if gate_status not in {
            "held",
            "blocked",
        }:
            errors.append(
                "unresolved disputes require "
                "a held or blocked settlement gate"
            )

        if royalty_status not in {
            "pending",
            "held",
            "blocked",
        }:
            errors.append(
                "unresolved disputes prohibit "
                "ready or completed royalty"
            )

    if royalty_status in {
        "ready",
        "completed",
    }:
        if audit_status != "completed":
            errors.append(
                "ready or completed royalty "
                "requires completed audit"
            )

        if responsibility_status not in {
            "completed",
            "not_applicable",
        }:
            errors.append(
                "ready or completed royalty requires "
                "completed or non-applicable "
                "responsibility"
            )

        if gate_status != "released":
            errors.append(
                "ready or completed royalty "
                "requires released settlement gate"
            )

        if unresolved:
            errors.append(
                "ready or completed royalty cannot "
                "retain unresolved disputes"
            )

    projected_decision = bridge.get(
        "authorization_projection",
        {},
    ).get(
        "projected_decision"
    )

    if (
        projected_decision
        in NON_EXECUTABLE_PROJECTIONS
        and royalty_status
        in {
            "ready",
            "completed",
        }
    ):
        errors.append(
            "non-executable authorization "
            "projection cannot release royalty"
        )

    linked_executions = [
        catalogs.executions[execution_id]
        for execution_id
        in handoff_execution_ids
        if execution_id
        in catalogs.executions
    ]

    has_violation = any(
        (
            execution.get("execution_status")
            == "blocked"
        )
        or (
            execution.get(
                "authorization_match",
                {},
            ).get("status")
            == "mismatched"
        )
        for execution in linked_executions
    )

    if has_violation:
        if audit_status == "not_applicable":
            errors.append(
                "blocked or mismatched execution "
                "requires audit handoff"
            )

        if (
            responsibility_status
            == "not_applicable"
        ):
            errors.append(
                "blocked or mismatched execution "
                "requires responsibility handoff"
            )

        if royalty_status in {
            "ready",
            "completed",
        }:
            errors.append(
                "blocked or mismatched execution "
                "cannot release royalty"
            )

        if gate_status not in {
            "held",
            "blocked",
        }:
            errors.append(
                "blocked or mismatched execution "
                "requires held or blocked "
                "settlement gate"
            )

    return errors


def validate_example(
    path: Path,
    expected_pass: bool,
    kind: str,
    validator: Draft202012Validator,
    catalogs: Catalogs,
) -> bool:
    """Validate one expected-pass or expected-fail example."""
    label = (
        "pass"
        if expected_pass
        else "fail"
    )

    print(
        f"\n[validate-{label}] "
        f"{path.relative_to(ROOT)}"
    )

    try:
        document = load_document(path)
    except (
        OSError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as exc:
        if expected_pass:
            print(f"[parse-error] {exc}")
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
        if kind == "bridge":
            semantic = bridge_semantic_errors(
                document,
                catalogs,
            )
        else:
            semantic = handoff_semantic_errors(
                document,
                catalogs,
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
    """Run all v0.5 validation checks."""
    print(
        "=== Cross-Protocol Authorization "
        "Bridge Validation ==="
    )

    try:
        validators = load_validators()
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

    receipts = load_catalog(
        "receipt",
        validators["receipt"],
    )

    executions = load_catalog(
        "execution",
        validators["execution"],
    )

    revocations = load_catalog(
        "revocation",
        validators["revocation"],
    )

    base_catalogs = Catalogs(
        receipts=receipts,
        executions=executions,
        revocations=revocations,
        bridges={},
    )

    bridge_pass_files = matching_files(
        PASS_DIR,
        PREFIXES["bridge"],
    )

    bridge_fail_files = matching_files(
        FAIL_DIR,
        PREFIXES["bridge"],
    )

    if (
        not bridge_pass_files
        or not bridge_fail_files
    ):
        print(
            "[fatal] bridge validation requires "
            "pass and fail examples"
        )
        return 1

    bridge_results = [
        validate_example(
            path,
            True,
            "bridge",
            validators["bridge"],
            base_catalogs,
        )
        for path in bridge_pass_files
    ]

    bridge_results.extend(
        validate_example(
            path,
            False,
            "bridge",
            validators["bridge"],
            base_catalogs,
        )
        for path in bridge_fail_files
    )

    bridges: dict[
        str,
        dict[str, Any],
    ] = {}

    for path in bridge_pass_files:
        document = load_document(path)

        if not isinstance(document, dict):
            continue

        if schema_errors(
            validators["bridge"],
            document,
        ):
            continue

        if bridge_semantic_errors(
            document,
            base_catalogs,
        ):
            continue

        bridge_id = document.get(
            "bridge_id"
        )

        if isinstance(bridge_id, str):
            bridges[bridge_id] = document

    full_catalogs = Catalogs(
        receipts=receipts,
        executions=executions,
        revocations=revocations,
        bridges=bridges,
    )

    handoff_pass_files = matching_files(
        PASS_DIR,
        PREFIXES["handoff"],
    )

    handoff_fail_files = matching_files(
        FAIL_DIR,
        PREFIXES["handoff"],
    )

    if (
        not handoff_pass_files
        or not handoff_fail_files
    ):
        print(
            "[fatal] handoff validation requires "
            "pass and fail examples"
        )
        return 1

    handoff_results = [
        validate_example(
            path,
            True,
            "handoff",
            validators["handoff"],
            full_catalogs,
        )
        for path in handoff_pass_files
    ]

    handoff_results.extend(
        validate_example(
            path,
            False,
            "handoff",
            validators["handoff"],
            full_catalogs,
        )
        for path in handoff_fail_files
    )

    results = (
        bridge_results
        + handoff_results
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
