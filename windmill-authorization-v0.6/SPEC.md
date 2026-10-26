# Action Authorization Receipt Protocol v0.6 — Windmill Blade Authorization Bridge

**Experimental supplemental profile**; keeps v0.5 receipt schemas and validation intact.

## Objective
Specify authorization constraints for a Kazene Windmill v1.0 blade replacement operation without conflating intent, authorization, execution evidence, lease revocation or independent recovery approval.

## Normative constraints
- Attack sources are untrusted inputs and MUST NOT authorize or execute control-plane decisions.
- A blade MUST NOT self-authorize repair, swap, recovery or release.
- Before swap execution, an independent approver MUST authorize the action, and signature, scope and identity checks MUST pass.
- An old blade lease MUST be revoked or fenced before the replacement gains active execution rights.
- New blade authority MUST NOT exceed independently approved scope; stale or implicitly inherited privileges are forbidden.
- Trace continuity MUST be verified independently of the replacement blade.
- Recovery approval and post-replacement health MUST precede resumed D/R mode.
- Any missing or unverifiable requirement MUST result in hold or denial rather than automatic release.

## Machine-checkable synthetic profile
`python3 windmill-authorization-v0.6/scripts/validate.py`

Cases are normalized projections, **not** real signed Action Authorization Receipts. This suite tests consistency of declarative allow/deny rules only. It does not execute swaps, verify cryptographic signatures or establish runtime safety.

## Relationship
Kazene Windmill: `SamuraiWriter7/kazene-os/windmill`
Resilient Safety: `SamuraiWriter7/resilient-ai-safety-principles/windmill-safety-v0.6`
Kazene Conformance: `SamuraiWriter7/kazene-protocol-conformance-suite/windmill-v0.6`
