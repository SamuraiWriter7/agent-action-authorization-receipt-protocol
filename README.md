# Agent Action Authorization Receipt Protocol

A vendor-neutral protocol for recording why, by whom, within which scope, and under which constraints an AI agent action was authorized, restricted, deferred, denied, revoked, executed, or handed off to downstream governance systems.

Current repository release:

```text
v0.5.0 — Cross-Protocol Authorization Bridge
```

## Overview

AI agents can call tools, access data, send messages, purchase services, modify records, invoke remote agents, and trigger digital or physical actions.

Technical capability does not establish authority.

```text
The agent can execute
        ≠
The agent may execute
```

This protocol places a machine-readable authorization boundary between action intent and execution.

```text
Origin
  ↓
Trace
  ↓
Policy / Risk / Human Review
  ↓
Action Authorization Receipt
  ↓
Scope and Constraint Gate
  ↓
Protocol Bridge
  ↓
Execution Evidence
  ↓
Audit / Dispute / Responsibility
  ↓
Royalty
```

The protocol records:

* what action was requested;
* which agent requested it;
* who or what issued the decision;
* why the decision was made;
* which policies and evidence supported it;
* whether human review was required;
* which tools, resources, operations, and data classes were authorized;
* which cost, duration, destination, and execution-count limits applied;
* whether the actual execution matched the authorization;
* whether the authorization was expired, revoked, or superseded;
* which external protocol carried the authorized action;
* which downstream governance systems received the result.

## Repository

```text
agent-action-authorization-receipt-protocol
```

## Description

```text
A vendor-neutral protocol for recording why, by whom, under which policies, scopes, risks, and human-review conditions an AI agent action was authorized, restricted, deferred, denied, revoked, executed, or transferred across protocols.
```

## Core principle

The protocol separates five different facts that must not be collapsed into one record.

```text
Intent
    What does the agent want to do?

Authorization
    Why may or may not the action proceed?

Execution
    What was actually attempted or performed?

Lifecycle
    Was the authorization expired, revoked, or superseded?

Downstream governance
    What must be audited, disputed, assigned, or settled?
```

Each fact is represented by an immutable, linked record.

## Record types

### 1. Action Authorization Receipt

Schema:

```text
schemas/action-authorization-receipt.schema.json
```

The receipt records the authorization decision, scope, constraints, policy basis, human review, risk assessment, and context lineage.

Current receipt schema version:

```text
0.3.0
```

The receipt remains unchanged in v0.4 and v0.5. Later repository releases add linked record types rather than rewriting the original authorization decision.

### 2. Authorization Execution Evidence

Schema:

```text
schemas/authorization-execution-evidence.schema.json
```

Version:

```text
0.4.0
```

This record captures the action that was actually attempted or executed and compares it with the source authorization.

It records:

* execution status;
* observed action;
* actual tool, resource, destination, and data classes;
* actual monetary cost;
* actual duration;
* parameter digest;
* authorization match result;
* machine-readable violations;
* execution-count consumption;
* outcome references.

### 3. Authorization Revocation Record

Schema:

```text
schemas/authorization-revocation-record.schema.json
```

Version:

```text
0.4.0
```

This immutable record disables or replaces an authorization without modifying the original receipt.

Supported lifecycle actions are:

```text
revoked
expired
superseded
```

### 4. Cross-Protocol Authorization Bridge

Schema:

```text
schemas/cross-protocol-authorization-bridge.schema.json
```

Version:

```text
0.5.0
```

This record projects an authorization decision into an execution protocol.

Supported protocol bindings are:

```text
mcp
a2a
http_api
local_agent
custom
```

### 5. Authorization Downstream Handoff

Schema:

```text
schemas/authorization-downstream-handoff.schema.json
```

Version:

```text
0.5.0
```

This record transfers authorization and execution evidence to:

```text
audit
dispute
responsibility
royalty
```

It also controls whether settlement may proceed, remain held, or be blocked.

## First authorization arc

The first protocol arc was completed through five releases.

```text
v0.1  Action Authorization Receipt
v0.2  Scope and Constraint Binding
v0.3  Policy and Human Decision Gate
v0.4  Execution Evidence and Revocation
v0.5  Cross-Protocol Authorization Bridge
```

### v0.1 — Action Authorization Receipt

Introduced the minimum authorization decision record.

```text
Who made the decision?
What action was evaluated?
What was the decision?
Why was it made?
When was it issued?
When does it expire?
```

### v0.2 — Scope and Constraint Binding

Bound the decision to an executable boundary.

```text
Which tools?
Which resources?
Which operations?
Which data classes?
Which destinations?
What cost limit?
What duration limit?
How many executions?
Which actions remain prohibited?
```

### v0.3 — Policy and Human Decision Gate

Connected authorization to its decision basis.

```text
Which policy rules were evaluated?
Which results were applied or overridden?
Was human review required?
What was the review result?
What risk was identified?
What residual risk remained?
Which Origin, Trace, precedence, human-axis, and handoff records were referenced?
```

### v0.4 — Execution Evidence and Revocation

Compared authorization with actual execution.

```text
What was actually attempted?
Did it match the authorization?
Which violations occurred?
Was the receipt expired or revoked?
Was the execution count exhausted?
Did the attempt consume authorization?
```

### v0.5 — Cross-Protocol Authorization Bridge

Projected authorization across protocol boundaries and into downstream governance.

```text
Which protocol carried the action?
Which authentication and scopes were used?
Did the protocol projection preserve the original decision?
Which execution evidence was linked?
Was audit completed?
Were disputes unresolved?
Could responsibility and royalty processing proceed?
```

## Authorization decisions

The Action Authorization Receipt supports six decisions.

| Decision                   | Meaning                                                                       |
| -------------------------- | ----------------------------------------------------------------------------- |
| `authorized`               | The action may proceed while the receipt remains valid.                       |
| `conditionally_authorized` | The action may proceed only while all recorded constraints are enforced.      |
| `human_review_required`    | The action must remain blocked until a new human-reviewed decision is issued. |
| `deferred`                 | The decision is postponed and execution remains blocked.                      |
| `denied`                   | The action must not proceed.                                                  |
| `revoked`                  | Previously granted authority is no longer valid.                              |

Positive decisions:

```text
authorized
conditionally_authorized
```

Blocking decisions:

```text
human_review_required
deferred
denied
revoked
```

A blocking decision must not retain executable authority.

```yaml
authorized_scope:
  tools: []
  resources: []
  operations: []
  data_classes: []

constraints:
  maximum_cost: null
  maximum_duration_seconds: null
  allowed_destinations: []
  prohibited_actions: []
  execution_count: 0
```

## Authorization projection

Cross-protocol bridges translate receipt decisions into protocol-facing decisions.

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

An expired receipt or an authorization with an effective revocation also projects to:

```text
revoke
```

A bridge must not weaken the source decision.

For example:

```text
conditionally_authorized
```

must not be projected as:

```text
allow
```

It must remain:

```text
allow_with_constraints
```

Otherwise, the constraints would disappear at the protocol boundary.

## Minimal authorization receipt

```yaml
schema_version: "0.3.0"

authorization_id: aar-20260722-0301
request_id: req-purchase-1042
agent_id: agent-procurement-01

requested_action:
  action_type: purchase_order.create
  summary: Create a purchase order for replacement safety gloves.
  tool_id: tool-procurement-api
  target_type: vendor_account
  target_id: vendor-acme-industrial
  destination_id: vendor-acme-industrial
  data_classes:
    - procurement.non_personal
  estimated_cost:
    currency: JPY
    amount: "8400"
  estimated_duration_seconds: 120
  parameters_digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

decision: conditionally_authorized

decision_reason:
  code: human_approved_with_limits
  summary: The purchase was approved within the recorded limits.
  evidence_refs:
    - policy:procurement-limit-v3
    - review:review-procurement-7781
    - risk:risk-assessment-0301

authorized_by:
  actor_type: human
  actor_id: user:operations-manager-07
  authority_basis: delegation:procurement-2026-q3

authorized_scope:
  tools:
    - tool-procurement-api
  resources:
    - vendor-acme-industrial
  operations:
    - purchase_order.create
  data_classes:
    - procurement.non_personal

constraints:
  maximum_cost:
    currency: JPY
    amount: "10000"
  maximum_duration_seconds: 300
  allowed_destinations:
    - vendor-acme-industrial
  prohibited_actions:
    - purchase_order.delete
    - vendor_account.modify
  execution_count: 1

policy_bindings:
  - policy_id: procurement-approval-policy
    policy_version: v3
    rule_id: human-review-over-5000-jpy
    result: require_human_review
    enforcement: applied
    evaluated_by: policy-engine-main
    evaluated_at: "2026-07-22T01:00:00Z"
    override_authority_ref: null
    evidence_refs:
      - policy:procurement-limit-v3#human-review-over-5000-jpy

human_review:
  required: true
  status: approved
  review_id: review-procurement-7781
  reviewer_id: user:operations-manager-07
  reviewed_at: "2026-07-22T01:03:00Z"
  rationale: The purchase is necessary and remains within budget.
  evidence_refs:
    - delegation:procurement-2026-q3

risk_assessment:
  assessment_id: risk-assessment-0301
  assessed_by: risk-engine-main
  assessed_at: "2026-07-22T00:59:30Z"
  risk_level: medium
  score: 42
  categories:
    - financial.commitment
    - external.transaction
  mitigations:
    - budget.cap
    - approved.vendor
    - single.execution
  residual_risk_level: low

context_bindings:
  origin_reference: origin:request-origin-1042
  trace_reference: trace:trace-20260722-8841
  precedence_reference: precedence:procurement-action-v2
  human_axis_reference: human-axis:operations-manager-control
  handoff_reference: handoff:procurement-agent-handoff-77

issued_at: "2026-07-22T01:04:00Z"
expires_at: "2026-07-22T01:34:00Z"
```

## Authorized scope

Every receipt defines four scope dimensions.

```yaml
authorized_scope:
  tools: []
  resources: []
  operations: []
  data_classes: []
```

### Tools

The exact tools that the agent may invoke.

### Resources

The exact records, accounts, files, devices, services, or other targets that the agent may access or modify.

### Operations

The exact action types that may be executed.

### Data classes

The exact data classifications that may be read, transformed, stored, or transmitted.

## Constraints

Every receipt defines execution constraints.

```yaml
constraints:
  maximum_cost: null
  maximum_duration_seconds: null
  allowed_destinations: []
  prohibited_actions: []
  execution_count: 0
```

### Monetary values

Monetary amounts are represented as decimal strings.

```yaml
maximum_cost:
  currency: JPY
  amount: "10000"
```

This avoids binary floating-point ambiguity.

### Execution count

The receipt remains immutable.

The execution ledger records consumption separately.

```yaml
execution_usage:
  consumed: true
  sequence_number: 1
  used_before: 0
  used_after: 1
```

A blocked execution does not consume authorization.

```yaml
execution_usage:
  consumed: false
  sequence_number: 2
  used_before: 1
  used_after: 1
```

## Human review

Human review is represented as an explicit state machine.

Supported statuses:

```text
not_required
pending
approved
rejected
expired
```

A pending review must not permit execution.

```yaml
decision: human_review_required

human_review:
  required: true
  status: pending
```

A positive authorization that depends on a human-review policy requires:

```yaml
human_review:
  required: true
  status: approved
```

Human approval does not automatically override critical residual risk.

```text
Human review is a decision gate.
It is not an exemption from risk controls.
```

## Risk assessment

Supported risk levels:

```text
negligible
low
medium
high
critical
```

The residual risk must not exceed the original risk level.

A positive decision must not retain:

```text
critical
```

residual risk.

High residual risk requires approved human review and at least one mitigation.

## Policy bindings

Each policy binding records:

```text
policy identifier
policy version
rule identifier
evaluation result
enforcement status
evaluation authority
evaluation time
override authority
evidence references
```

Supported policy results:

```text
allow
deny
require_human_review
constrain
no_effect
```

Supported enforcement states:

```text
applied
overridden
advisory
```

A positive decision cannot retain an applied denial.

An overridden policy result must identify the authority responsible for the override.

## Execution evidence

Execution evidence records whether observed behavior matched the authorization.

Supported execution statuses:

```text
started
succeeded
failed
blocked
cancelled
```

Supported authorization-match statuses:

```text
matched
mismatched
```

Example:

```yaml
authorization_match:
  status: mismatched
  checked_by: execution-gate-main
  checked_at: "2026-07-22T01:21:00Z"
  violations:
    - code: authorization_revoked
      field: authorization_id
      expected: active authorization
      observed: arr-20260722-0401
```

## Violation vocabulary

Execution evidence may declare the following violation codes:

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

Declared violations must exactly match the violations computed from the linked receipt, revocation records, and execution evidence.

When violations exist:

```text
authorization_match.status = mismatched
execution_status = blocked
execution_usage.consumed = false
```

## Revocation and supersession

The original authorization receipt is immutable.

A separate lifecycle record changes whether the authorization may be used.

```text
Action Authorization Receipt
        remains unchanged

Authorization Revocation Record
        disables or replaces future use
```

A supersession record must identify the replacement authorization.

```yaml
revocation_type: superseded
superseding_authorization_id: aar-replacement-0001
```

## Protocol bindings

### MCP

An MCP bridge may include:

```text
endpoint
operation
capability identifier
resource indicator
required scopes
OAuth credential reference
audience
issuer
transport evidence
```

The bridge preserves the higher-level action authorization while the protocol handles transport-level authentication and resource access.

### A2A

An A2A bridge may include:

```text
Agent Card reference
capability identifier
security scheme references
required scopes
authentication information
transport evidence
```

The bridge records why the requested agent action may proceed, remain blocked, or require human review.

### HTTP API

An HTTP API bridge requires an HTTP method.

```text
GET
POST
PUT
PATCH
DELETE
OPTIONS
HEAD
```

### Local agent

A local-agent binding identifies the local capability without remote transport fields.

### Custom protocol

A custom binding requires an extension reference that defines its protocol-specific interpretation.

## Credential handling

Secrets must not be embedded directly in bridge records.

Use stable references instead.

```yaml
credential_reference: vault:credential/mcp-procurement-session
```

The receipt or bridge may identify the credential location, but it must not contain:

```text
access tokens
API secrets
private keys
passwords
raw session credentials
```

## Downstream handoff

The downstream handoff sends authorization and execution evidence into four governance domains.

```yaml
destinations:
  audit:
    status: completed
    record_refs: []

  dispute:
    status: not_applicable
    record_refs: []

  responsibility:
    status: completed
    record_refs: []

  royalty:
    status: ready
    record_refs: []
```

Supported destination statuses:

```text
not_applicable
pending
ready
completed
held
blocked
```

## Settlement gate

Supported settlement states:

```text
open
held
blocked
released
```

Royalty may become `ready` or `completed` only when:

```text
audit is completed
responsibility is completed or not applicable
the settlement gate is released
no unresolved dispute remains
no linked execution is blocked or mismatched
```

A blocked or mismatched execution requires:

```text
audit handoff
responsibility handoff
held or blocked settlement gate
royalty hold
```

## Repository structure

```text
agent-action-authorization-receipt-protocol/
├── .github/
│   └── workflows/
│       └── validate.yml
├── examples/
│   ├── fail/
│   │   ├── action-authorization-receipt.*
│   │   ├── authorization-downstream-handoff.*
│   │   ├── authorization-execution-evidence.*
│   │   ├── authorization-revocation-record.*
│   │   └── cross-protocol-authorization-bridge.*
│   └── pass/
│       ├── action-authorization-receipt.*
│       ├── authorization-downstream-handoff.*
│       ├── authorization-execution-evidence.*
│       ├── authorization-revocation-record.*
│       └── cross-protocol-authorization-bridge.*
├── schemas/
│   ├── action-authorization-receipt.schema.json
│   ├── authorization-downstream-handoff.schema.json
│   ├── authorization-execution-evidence.schema.json
│   ├── authorization-revocation-record.schema.json
│   └── cross-protocol-authorization-bridge.schema.json
├── scripts/
│   ├── validate_bridge_records.py
│   ├── validate_examples.py
│   └── validate_execution_records.py
├── spec/
│   └── action-authorization-receipt.md
├── CHANGELOG.md
├── LICENSE
├── README.md
└── requirements-dev.txt
```

## Validation

Install development dependencies:

```bash
python -m pip install -r requirements-dev.txt
```

Run the authorization receipt validator:

```bash
python scripts/validate_examples.py
```

Run the execution and revocation validator:

```bash
python scripts/validate_execution_records.py
```

Run the protocol bridge and downstream handoff validator:

```bash
python scripts/validate_bridge_records.py
```

Run all validation stages:

```bash
python scripts/validate_examples.py
python scripts/validate_execution_records.py
python scripts/validate_bridge_records.py
```

Expected final result from each validator:

```text
Validation completed successfully.
```

## Validator boundaries

Each validator processes only its own filename prefix.

```text
validate_examples.py
    action-authorization-receipt.*

validate_execution_records.py
    authorization-execution-evidence.*
    authorization-revocation-record.*

validate_bridge_records.py
    cross-protocol-authorization-bridge.*
    authorization-downstream-handoff.*
```

This prevents one record type from being evaluated against another record type’s schema.

## Validation layers

The repository uses two validation layers.

```text
JSON Schema validation
        +
cross-record semantic validation
```

JSON Schema validates:

```text
required fields
types
enumerations
patterns
unknown properties
basic structural constraints
```

Semantic validators check:

```text
timestamp ordering
decision and scope consistency
policy-result consistency
human-review state transitions
risk constraints
cost and duration limits
execution-count consumption
revocation effectiveness
execution-to-authorization differences
protocol decision projection
authentication scope coverage
bridge-to-execution linkage
audit and royalty ordering
dispute and settlement gates
```

## Expected-pass and expected-fail examples

The repository includes both valid and intentionally invalid examples.

CI succeeds only when:

```text
valid examples are accepted
        and
invalid examples are rejected
```

An invalid example that unexpectedly passes causes the workflow to fail.

## GitHub Actions

The validation workflow runs three stages.

```text
Validate authorization receipts
        ↓
Validate execution and revocation records
        ↓
Validate protocol bridges and handoffs
```

Workflow file:

```text
.github/workflows/validate.yml
```

## Security considerations

Authorization records can expose sensitive operational metadata.

Implementations should minimize direct inclusion of:

```text
personal data
confidential policy content
private evidence
secrets
credentials
internal network details
unnecessary action parameters
```

Stable references should be preferred.

A structurally valid receipt does not, by itself, prove that:

```text
the issuer was legitimate
the human reviewer was authorized
the evidence was authentic
the delegation chain was valid
the linked policy was trustworthy
the storage layer was tamper resistant
```

Implementations must separately protect:

```text
issuer identity
delegation chains
credential stores
receipt integrity
canonical serialization
digital signatures
evidence storage
revocation distribution
execution counters
access control
```

## Immutability

The protocol is based on immutable linked records.

```text
Authorization decisions are not rewritten by execution.

Execution evidence is not rewritten by revocation.

Revocation records do not erase historical authorization.

Downstream handoffs do not alter source evidence.
```

Changes are represented by new records linked through stable identifiers.

## Interoperability position

This protocol does not replace transport authentication or protocol-native authorization.

It complements them.

```text
Protocol-native authorization
    Can this client access this server, resource, or operation?

Action Authorization Receipt
    Why may this particular agent perform this particular action,
    under which conditions, and with whose authority?
```

The protocol is intended to remain:

```text
vendor neutral
transport neutral
model neutral
agent-framework neutral
ledger neutral
```

## First-arc completion

The completed first arc is:

```text
Origin
  ↓
Trace
  ↓
Policy
  ↓
Risk
  ↓
Human Gate
  ↓
Authorization
  ↓
Scope and Constraints
  ↓
Protocol Bridge
  ↓
Execution Evidence
  ↓
Audit
  ↓
Dispute / Responsibility
  ↓
Royalty
```

Origin explains where the action came from.

Trace explains what led to the request.

Policy, risk, and human review explain why the decision was made.

Authorization explains whether the action may proceed.

Scope and constraints explain how far the authority extends.

Execution evidence explains what actually happened.

Revocation explains why authority ceased to be valid.

The protocol bridge preserves the decision across execution environments.

Audit, dispute, responsibility, and royalty determine what happens after execution.

## License

MIT License.

See:

```text
LICENSE
```
