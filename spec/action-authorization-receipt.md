# Action Authorization Receipt Specification

Version: `0.2.0`

Status: Scope and Constraint Binding

## 1. Objective

The Action Authorization Receipt records:

1. whether an AI agent action may proceed;
2. which tools, resources, operations,
   and data classes are authorized;
3. which cost, duration, destination,
   prohibition, and execution-count
   constraints apply.

The receipt creates a machine-readable
execution boundary.

```text
Action Intent
    ↓
Authorization Decision
    ↓
Authorized Scope
    ↓
Constraint Evaluation
    ↓
Execution Gate
    ↓
Execution
2. Normative terms

The terms MUST, MUST NOT, SHOULD,
SHOULD NOT, and MAY indicate protocol
requirements and recommendations.

3. Conformance

A v0.2 receipt conforms when:

it validates against
schemas/action-authorization-receipt.schema.json;
it satisfies all semantic invariants;
its execution controller enforces the
authorized scope and constraints;
blocked decisions never permit execution.
4. Required receipt fields

A receipt MUST contain:

schema_version
authorization_id
request_id
agent_id
requested_action
decision
decision_reason
authorized_by
authorized_scope
constraints
issued_at
expires_at

Unknown properties MUST be rejected.

5. Requested action

requested_action MUST contain:

action_type
summary

It MAY contain:

tool_id
target_type
target_id
destination_id
data_classes
estimated_cost
estimated_duration_seconds
parameters_digest

When either target_type or target_id
is present, both MUST be present.

6. Authorized scope

authorized_scope MUST contain:

tools
resources
operations
data_classes

Each field MUST be an array.

6.1 Tools

tools identifies the exact tools
that may be invoked.

When requested_action.tool_id is present
for a positive decision, it MUST appear
in authorized_scope.tools.

6.2 Resources

resources identifies the exact resources
that may be accessed or modified.

When requested_action.target_id is present
for a positive decision, it MUST appear
in authorized_scope.resources.

6.3 Operations

operations identifies the exact action
types that may be executed.

For a positive decision:

operations MUST NOT be empty;
requested_action.action_type
MUST appear in operations.
6.4 Data classes

data_classes identifies the permitted
data classifications.

Every value in
requested_action.data_classes
MUST appear in
authorized_scope.data_classes.

An empty array means that the authorization
does not grant access to classified data.

7. Constraints

constraints MUST contain:

maximum_cost
maximum_duration_seconds
allowed_destinations
prohibited_actions
execution_count
7.1 Maximum cost

maximum_cost MUST be either:

currency and decimal amount
or
null

A null value means that the receipt does
not authorize positive monetary spending.

When the requested action contains a
positive estimated_cost:

maximum_cost MUST be present;
the currencies MUST match;
the estimated amount MUST NOT exceed
the maximum amount.

Amounts MUST be encoded as decimal strings.

This avoids binary floating-point ambiguity.

7.2 Maximum duration

maximum_duration_seconds MUST be either:

a positive integer
or
null

When both estimated and maximum durations
are present, the estimated duration MUST NOT
exceed the maximum.

A null value means that v0.2 does not impose
a protocol-level duration limit.

7.3 Allowed destinations

allowed_destinations identifies exact
destinations to which the action may send
or deliver data, funds, messages, or results.

When requested_action.destination_id
is present for a positive decision,
it MUST appear in allowed_destinations.

An empty array means that no external
destination is authorized.

7.4 Prohibited actions

prohibited_actions records operations
that remain forbidden even when related
operations are permitted.

For a positive decision,
requested_action.action_type
MUST NOT appear in prohibited_actions.

7.5 Execution count

execution_count records the maximum
number of executions authorized by
the receipt.

For a positive decision, it MUST be
at least 1.

For a blocking decision, it MUST be 0.

The receipt itself is immutable.

Execution counters SHOULD be maintained
in an external execution ledger until
v0.4 defines execution evidence.

8. Decision semantics

Positive decisions are:

authorized
conditionally_authorized

Blocking decisions are:

human_review_required
deferred
denied
revoked
9. Positive-decision invariants

For a positive decision:

the action type MUST be authorized;
the tool, when supplied, MUST be authorized;
the target, when supplied, MUST be authorized;
all data classes MUST be authorized;
the destination, when supplied,
MUST be authorized;
the action MUST NOT be prohibited;
the cost limit MUST be respected;
the duration limit MUST be respected;
the execution count MUST be at least one;
the receipt MUST not be expired.
10. Blocking-decision invariants

For a blocking decision:

authorized_scope:
  tools: []
  resources: []
  operations: []
  data_classes: []

MUST be used.

The following MUST also hold:

constraints:
  execution_count: 0

A blocking decision MUST NOT retain
executable authority.

prohibited_actions MAY identify the
operation that caused the denial.

11. Execution gate

Before execution, the controller MUST verify:

receipt decision
receipt expiration
agent identity
action type
tool identity
resource identity
data classification
destination
cost
duration
execution count
prohibited operations
parameter digest

A mismatch MUST block execution.

12. Compatibility

Version 0.2 extends v0.1 with:

requested action metadata
authorized_scope
constraints
scope semantic validation
cost semantic validation
duration semantic validation
blocking-decision validation

A v0.1 receipt does not automatically
conform to v0.2.

Migration requires:

changing schema_version to 0.2.0;
adding authorized_scope;
adding constraints;
ensuring blocked decisions use empty scope;
ensuring blocked decisions use
execution_count: 0.
13. Reserved areas

Version 0.2 does not yet standardize:

policy evaluation graphs
human review records
risk assessments
precedence resolution
origin bindings
trace bindings
execution evidence
scope consumption ledgers
revocation chains
transport bindings

These enter in v0.3 through v0.5.

14. Validation

The reference validator is:

scripts/validate_examples.py

It performs:

JSON Schema validation
        +
cross-field semantic validation
