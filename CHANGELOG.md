# Changelog

All notable changes to the Agent Action Authorization Receipt Protocol are documented in this file.

The project follows a staged protocol-development model.

```text
v0.1  Action Authorization Receipt
v0.2  Scope and Constraint Binding
v0.3  Policy and Human Decision Gate
v0.4  Execution Evidence and Revocation
v0.5  Cross-Protocol Authorization Bridge
```

## [0.5.0] - 2026-07-22

### Added

* Cross-Protocol Authorization Bridge record.
* Authorization Downstream Handoff record.
* Cross-protocol bridge JSON Schema.
* Downstream handoff JSON Schema.
* Cross-record bridge and handoff validator.
* Dedicated CI validation stage for v0.5 records.
* Protocol binding support for:

  * MCP;
  * A2A;
  * HTTP APIs;
  * local agents;
  * custom protocols.
* Protocol version recording.
* Endpoint recording.
* Operation and capability identifiers.
* Security scheme references.
* Authentication scheme recording.
* External credential references.
* Requested and required protocol scopes.
* Authentication audiences.
* Authentication issuers.
* MCP resource-indicator binding.
* A2A Agent Card binding.
* HTTP method binding.
* Local-agent capability binding.
* Custom-protocol extension references.
* Authorization decision projection.
* Source-decision snapshots.
* Authorized-scope snapshots.
* Constraint snapshots.
* Parameter-digest projection.
* Authorization-expiration projection.
* Transport request digests.
* Transport response digests.
* Transport response codes.
* Transport evidence references.
* Bridge-to-execution evidence linkage.
* Audit handoff destination.
* Dispute handoff destination.
* Responsibility handoff destination.
* Royalty handoff destination.
* Settlement release, hold, block, and open states.
* Unresolved-dispute references.
* MCP completed bridge passing example.
* MCP revoked bridge passing example.
* A2A human-challenge passing example.
* Released downstream handoff passing example.
* Held downstream handoff passing example.
* Decision-projection mismatch failing example.
* Authentication-scope mismatch failing example.
* Royalty-before-audit failing example.
* Unresolved-dispute release failing example.

### Authorization projection

Source authorization decisions are projected as follows:

```text
authorized
    → allow

conditionally_authorized
    → allow_with_constraints

human_review_required
    → human_challenge

deferred
    → defer

denied
    → deny

revoked
    → revoke
```

An expired authorization or an authorization with an effective revocation projects to:

```text
revoke
```

### Protocol validation

* Required scopes must be covered by requested authentication scopes.
* An authentication scheme of `none` must not include credentials, scopes, audiences, issuers, or security scheme references.
* Authenticated bindings must include a credential reference.
* MCP bindings must include a resource indicator.
* MCP resource indicators must match the endpoint.
* MCP authentication audiences must match the resource indicator when present.
* MCP bindings must not use A2A, HTTP-only, or custom-extension fields.
* A2A bindings must include an Agent Card reference.
* A2A bindings must include a capability identifier.
* Authenticated A2A bindings must include security scheme references.
* A2A bindings must not use MCP, HTTP-only, or custom-extension fields.
* HTTP API bindings must include an HTTP method.
* Local-agent bindings must include a capability identifier.
* Custom-protocol bindings must include an extension reference.

### Bridge validation

* Bridge authorization IDs must resolve to passing authorization receipts.
* Projected decisions must match the source receipt and active lifecycle state.
* Scope snapshots must exactly match the source receipt.
* Constraint snapshots must exactly match the source receipt.
* Request IDs must match the source receipt.
* Agent IDs must match the source receipt.
* Action types must match the source receipt.
* Parameter digests must match the source receipt.
* Expiration timestamps must match the source receipt.
* Bridge creation time must not precede transport binding time.
* Non-executable projections must use blocked transport status.
* Completed executable bridges must link execution evidence.
* Prepared bridges must not contain response evidence.
* Prepared bridges must not link execution evidence.
* Linked execution evidence must resolve to passing records.
* Linked execution evidence must belong to the same authorization.
* Linked execution request and agent identifiers must match the receipt.
* Non-executable projections must not link non-blocked executions.

### Downstream validation

* Downstream handoff bridge IDs must resolve to passing bridge records.
* Handoff authorization IDs must match the bridge.
* Handoff execution evidence IDs must exactly match the bridge.
* Handoff emission time must not precede bridge creation time.
* `not_applicable` destinations must not contain record references.
* `ready` and `completed` destinations must contain record references.
* Released settlement gates require:

  * a null reason code;
  * no unresolved disputes;
  * dispute completion or non-applicability.
* Held or blocked settlement gates require a reason code.
* Unresolved disputes require a held or blocked settlement gate.
* Unresolved disputes prohibit royalty release.
* Ready or completed royalty requires:

  * completed audit;
  * completed or non-applicable responsibility;
  * a released settlement gate;
  * no unresolved disputes.
* Non-executable authorization projections cannot release royalty.
* Blocked or mismatched executions require audit handoff.
* Blocked or mismatched executions require responsibility handoff.
* Blocked or mismatched executions require held or blocked settlement.
* Blocked or mismatched executions cannot release royalty.

### Architectural decision

Authorization is projected into external protocols without replacing their native authentication or authorization systems.

```text
Transport authorization
    Determines whether a client may access a server,
    resource, endpoint, or protocol operation.

Action authorization
    Determines why a specific AI agent action may proceed,
    within which limits, and under whose authority.
```

The bridge preserves the action-level authorization decision across protocol boundaries.

### Architectural completion

v0.5 completes the first authorization arc.

```text
Origin
  ↓
Trace
  ↓
Policy / Risk / Human Review
  ↓
Authorization
  ↓
Scope and Constraints
  ↓
Protocol Bridge
  ↓
Execution Evidence
  ↓
Audit / Dispute / Responsibility
  ↓
Royalty
```

### Compatibility

* The v0.3 Action Authorization Receipt schema remains unchanged.
* The v0.4 execution evidence and revocation schemas remain unchanged.
* v0.5 adds new linked record types.
* Existing v0.3 receipts and v0.4 lifecycle records do not need to be rewritten.
* v0.5 bridge records require passing source receipts.
* v0.5 handoff records require passing bridge records.

## [0.4.0] - 2026-07-22

### Added

* Authorization Execution Evidence record.
* Authorization Revocation Record.
* Execution evidence JSON Schema.
* Revocation record JSON Schema.
* Cross-record execution and revocation validator.
* Dedicated CI validation stage for v0.4 records.
* Observed-action recording.
* Execution status vocabulary:

  * `started`;
  * `succeeded`;
  * `failed`;
  * `blocked`;
  * `cancelled`.
* Authorization match states:

  * `matched`;
  * `mismatched`.
* Actual action type recording.
* Actual tool identifier recording.
* Actual target identifier recording.
* Actual destination identifier recording.
* Actual data-class recording.
* Actual cost recording.
* Actual duration recording.
* Actual parameter-digest recording.
* Execution-count consumption tracking.
* Execution sequence numbers.
* Outcome evidence references.
* Machine-readable authorization violation codes.
* Revocation lifecycle types:

  * `revoked`;
  * `expired`;
  * `superseded`.
* Revocation issue and effective timestamps.
* Superseding authorization linkage.
* Affected execution references.
* Successful execution passing example.
* Revocation passing example.
* Blocked-after-revocation passing example.
* Scope-mismatch failing example.
* After-revocation execution failing example.
* Invalid supersession failing example.

### Violation vocabulary

Added support for:

```text
decision_blocking
receipt_expired
authorization_revoked
request_mismatch
agent_mismatch
action_type_out_of_scope
tool_out_of_scope
resource_out_of_scope
data_class_out_of_scope
destination_out_of_scope
cost_limit_exceeded
duration_limit_exceeded
execution_count_exceeded
prohibited_action
parameters_digest_mismatch
```

### Execution validation

* Execution evidence must resolve to a passing authorization receipt.
* Request IDs must match the receipt.
* Agent IDs must match the receipt.
* Blocking decisions must not execute.
* Expired receipts must block execution.
* Effective revocations must block execution.
* Action types must remain inside the authorized operation scope.
* Tools must remain inside the authorized tool scope.
* Resources must remain inside the authorized resource scope.
* Data classes must remain inside the authorized data-class scope.
* Destinations must remain inside allowed destinations.
* Prohibited actions must remain blocked.
* Actual monetary cost must not exceed the authorized maximum.
* Actual cost currency must match the authorization currency.
* Actual duration must not exceed the authorized maximum.
* Exhausted execution counts must block execution.
* Parameter digests must match when the source receipt provides one.
* Declared violations must exactly match computed violations.
* Executions with violations must be:

  * `mismatched`;
  * `blocked`;
  * non-consuming.
* Executions without violations must be:

  * `matched`;
  * non-blocked.
* Blocked attempts must not consume execution count.
* Non-blocked attempts consume one execution count.
* `used_after` must reflect whether authorization was consumed.
* Sequence numbers must remain consistent with execution usage.
* Started executions require a start time and null completion time.
* Succeeded, failed, and cancelled executions require start and completion times.
* Blocked executions require null start and completion times.
* Completion time must not precede start time.
* Authorization checking must occur no later than execution start.
* Evidence recording time must not precede the latest recorded event.

### Revocation validation

* Revocation authorization IDs must resolve to passing receipts.
* Effective time must not precede issue time.
* `superseded` records must identify a replacement authorization.
* Non-supersession records must not contain a replacement authorization.
* A superseding authorization must differ from the revoked authorization.
* Delegated-agent revocation requires a delegation identifier.
* Other revocation authority types must not include a delegation identifier.

### Architectural decision

The source authorization receipt remains immutable.

Execution and lifecycle facts are represented by separate linked records.

```text
Action Authorization Receipt
        ├── Authorization Execution Evidence
        └── Authorization Revocation Record
```

This prevents execution-time evidence from rewriting the original authorization decision.

### Compatibility

* The v0.3 receipt schema remains valid and unchanged.
* v0.4 introduces linked record types.
* Existing v0.3 receipts do not require migration.
* v0.4 execution records require a passing v0.3 receipt.

## [0.3.0] - 2026-07-22

### Added

* Policy and Human Decision Gate.
* Policy-binding records.
* Human-review state machine.
* Risk-assessment record.
* Context bindings.
* Policy identifier and version fields.
* Policy rule identifiers.
* Policy evaluation results.
* Policy enforcement states.
* Policy evaluator identifiers.
* Policy evaluation timestamps.
* Policy override-authority references.
* Policy evidence references.
* Human-review requirement flag.
* Human-review status.
* Human-review identifiers.
* Reviewer identifiers.
* Review timestamps.
* Human-review rationale.
* Human-review evidence references.
* Risk assessment identifier.
* Risk assessor identifier.
* Risk assessment timestamp.
* Initial risk level.
* Numerical risk score.
* Risk categories.
* Mitigation identifiers.
* Residual risk level.
* Origin reference.
* Trace reference.
* Structural precedence reference.
* Human-axis reference.
* Agent handoff reference.
* Approved human-review passing example.
* Denied policy decision passing example.
* Pending human-review passing example.
* Applied-denial conflict failing example.
* Pending-review positive-decision failing example.
* Critical residual-risk positive-decision failing example.

### Policy vocabulary

Added policy results:

```text
allow
deny
require_human_review
constrain
no_effect
```

Added enforcement states:

```text
applied
overridden
advisory
```

### Human-review vocabulary

Added statuses:

```text
not_required
pending
approved
rejected
expired
```

### Risk vocabulary

Added levels:

```text
negligible
low
medium
high
critical
```

### Policy validation

* An overridden policy must identify the override authority.
* Non-overridden policies must not include an override authority.
* Positive decisions cannot retain an applied denial.
* `human_review_required` decisions require an applied human-review policy result.
* Denied decisions require:

  * an applied denial; or
  * a rejected human review.
* Positive decisions with an applied human-review requirement require approved human review.

### Human-review validation

* Reviews marked not required must use `not_required`.
* Reviews marked not required must not contain reviewer decision fields.
* Required reviews cannot use `not_required`.
* Pending reviews require a review identifier.
* Pending reviews must not contain reviewer, review time, or rationale.
* Completed reviews require:

  * review identifier;
  * reviewer identifier;
  * review timestamp;
  * rationale.
* `human_review_required` decisions require:

  * `required: true`;
  * `status: pending`.
* Positive decisions cannot have:

  * pending review;
  * rejected review;
  * expired review.
* Denied decisions cannot contain approved human review.

### Risk validation

* Residual risk must not exceed initial risk.
* Positive decisions cannot retain critical residual risk.
* High residual risk requires approved human review.
* High residual risk requires at least one mitigation.

### Changed

* Receipt schema version updated from `0.2.0` to `0.3.0`.
* Authorization receipts now include decision provenance.
* Authorization receipts now connect to Origin and Trace records.
* Authorization receipts now include human-review state.
* Authorization receipts now include risk assessment and mitigation evidence.
* Policy versions use a dedicated version-identifier definition so short forms such as `v3` remain valid.

### Compatibility

v0.2 receipts require migration before they conform to v0.3.

Required additions:

```text
policy_bindings
human_review
risk_assessment
context_bindings
```

The schema version must be updated to:

```text
0.3.0
```

## [0.2.0] - 2026-07-22

### Added

* Authorized Scope object.
* Constraint object.
* Tool-level authorization.
* Resource-level authorization.
* Operation-level authorization.
* Data-class authorization.
* Requested tool identifier.
* Requested destination identifier.
* Requested data classifications.
* Estimated monetary cost.
* Estimated execution duration.
* Maximum monetary cost.
* Maximum execution duration.
* Destination allowlist.
* Prohibited-action list.
* Execution-count limit.
* Decimal-string monetary representation.
* Positive constrained-authorization passing example.
* Denied empty-scope passing example.
* Operation-scope mismatch failing example.
* Cost-limit failing example.
* Blocking-decision executable-scope failing example.

### Scope fields

Added:

```text
tools
resources
operations
data_classes
```

### Constraint fields

Added:

```text
maximum_cost
maximum_duration_seconds
allowed_destinations
prohibited_actions
execution_count
```

### Scope validation

* Positive decisions must include at least one authorized operation.
* Requested actions must appear in authorized operations.
* Requested tools must appear in authorized tools.
* Requested targets must appear in authorized resources.
* Requested data classes must appear in authorized data classes.
* Requested destinations must appear in allowed destinations.
* Requested actions must not appear in prohibited actions.

### Constraint validation

* Positive-cost actions require a maximum cost.
* Estimated and maximum cost currencies must match.
* Estimated cost must not exceed maximum cost.
* Estimated duration must not exceed maximum duration.
* Positive decisions must authorize at least one execution.
* Blocking decisions must use zero execution count.
* Blocking decisions must have empty executable scope.

### Changed

* Receipt schema version updated from `0.1.0` to `0.2.0`.
* Authorization changed from a simple decision record to an enforceable execution boundary.
* Requested-action metadata was expanded.
* Semantic validation was expanded to include scope, destination, cost, duration, prohibition, and execution-count checks.

### Compatibility

v0.1 receipts require migration before they conform to v0.2.

Required additions:

```text
authorized_scope
constraints
```

The schema version must be updated to:

```text
0.2.0
```

## [0.1.0] - 2026-07-22

### Added

* Initial Action Authorization Receipt specification.
* Initial JSON Schema using Draft 2020-12.
* Initial Python reference validator.
* Initial GitHub Actions validation workflow.
* Expected-pass examples.
* Intentionally invalid expected-fail example.
* Authorization receipt identifiers.
* Request identifiers.
* Agent identifiers.
* Requested-action object.
* Action type.
* Human-readable action summary.
* Optional target type.
* Optional target identifier.
* Optional parameter digest.
* Authorization decision.
* Decision reason.
* Decision evidence references.
* Decision authority.
* Authority basis.
* Delegated-agent authority support.
* Authorization issue timestamp.
* Authorization expiration timestamp.

### Decision vocabulary

Introduced:

```text
authorized
conditionally_authorized
human_review_required
deferred
denied
revoked
```

### Authority vocabulary

Introduced:

```text
human
policy_engine
delegated_agent
system
```

### Validation

* Required fields must be present.
* Unknown fields are rejected.
* `target_type` and `target_id` must appear together.
* Parameter digests must use SHA-256 format.
* Delegated-agent authorities require a delegation identifier.
* Non-delegated authorities must not use a delegation identifier.
* Timestamps must include time-zone information.
* A non-null expiration time must be later than the issue time.
* Expected-pass examples must validate successfully.
* Expected-fail examples must be rejected.

### Protocol boundary

v0.1 established the first machine-readable boundary between action intent and execution.

```text
Action Intent
    ↓
Action Authorization Receipt
    ↓
Execution Gate
```

### Initial principle

```text
Origin explains where an action came from.

Trace explains what happened.

Authorization explains why execution was permitted or blocked.

Audit determines whether execution was correct.

Royalty determines where generated value should return.
```
