# Action Authorization Receipt Specification

Version: `0.1.0`

Status: Initial protocol release

## 1. Objective

The Action Authorization Receipt records the decision
governing whether a specific AI agent action may proceed.

It creates a machine-readable boundary between
action intent and action execution.

```text
Action Intent
    ↓
Authorization Receipt
    ↓
Execution Gate
    ↓
Execution
2. Normative terms

The terms MUST, MUST NOT, SHOULD, SHOULD NOT,
and MAY indicate protocol requirements
and recommendations.

3. Conformance target

A document conforms to v0.1 when:

it validates against
schemas/action-authorization-receipt.schema.json;
it satisfies the semantic invariants
defined in this specification;
its execution controller interprets
the decision according to Section 6.
4. Receipt object

A receipt MUST contain:

schema_version
authorization_id
request_id
agent_id
requested_action
decision
decision_reason
authorized_by
issued_at
expires_at

Unknown properties MUST be rejected.

5. Field requirements
5.1 schema_version

The value MUST be:

0.1.0
5.2 authorization_id

The value MUST uniquely identify the receipt
within the implementing system.

5.3 request_id

The value MUST identify the action request
being evaluated.

5.4 agent_id

The value MUST identify the agent expected
to perform the requested action.

A receipt MUST NOT be silently reused
by a different agent.

5.5 requested_action

The object MUST include:

action_type
summary

The object MAY include:

target_type
target_id
parameters_digest

When either target_type or target_id
is present, both MUST be present.

When parameters_digest is present,
it MUST use the form:

sha256:<64 hexadecimal characters>
5.6 decision

The value MUST be one of:

authorized
conditionally_authorized
human_review_required
deferred
denied
revoked
5.7 decision_reason

The object MUST include:

code
summary
evidence_refs

evidence_refs MAY be empty.

Implementations SHOULD use stable identifiers
rather than embedding sensitive evidence.

5.8 authorized_by

The object identifies the authority
that issued the decision.

This includes decisions that do not grant
authorization, such as denial or deferral.

It MUST include:

actor_type
actor_id
authority_basis

actor_type MUST be one of:

human
policy_engine
delegated_agent
system

When actor_type is delegated_agent,
delegation_id MUST be present.

When actor_type is not delegated_agent,
delegation_id MUST NOT be present.

5.9 issued_at

The value MUST be a timezone-aware timestamp.

5.10 expires_at

The value MUST be either:

a timezone-aware timestamp
null

When it is a timestamp,
it MUST be later than issued_at.

6. Execution semantics
6.1 Positive decisions

An execution controller MAY permit execution
when the decision is:

authorized
conditionally_authorized

The receipt MUST remain valid
at execution time.

For conditionally_authorized,
the controller MUST ensure that
the relevant conditions are enforced.

Version 0.1 records those conditions through
the reason summary and evidence references.

Machine-readable constraints will be defined
in v0.2.

6.2 Blocking decisions

An execution controller MUST block execution
when the decision is:

human_review_required
deferred
denied
revoked
6.3 Expiration

When expires_at is non-null
and the current time is equal to or later
than that timestamp, the controller MUST
treat the receipt as invalid for new execution.

6.4 Parameter binding

When parameters_digest is present,
an execution controller SHOULD calculate
the digest of the action parameters
and compare it before execution.

A mismatch MUST invalidate the receipt
for that execution attempt.

7. Receipt lifecycle

Version 0.1 models one authorization decision
per receipt.

A later decision SHOULD produce a new receipt
with a new authorization_id.

Direct revocation-event linkage,
supersession chains, and execution evidence
are reserved for v0.4.

8. Integrity

Implementations SHOULD protect receipts
against unauthorized modification.

Version 0.1 does not prescribe:

signature format
canonical serialization
ledger implementation
trust framework
9. Privacy

Implementations SHOULD avoid placing
the following directly inside a receipt:

secrets
credentials
personal data
confidential policy text
raw private evidence

Stable references SHOULD be used instead.

Those references SHOULD be protected
according to their sensitivity.

10. Validation

The reference validator is:

scripts/validate_examples.py

It validates both expected-pass
and expected-fail examples.
