"""Windmill blade authorization v0.6 supplemental synthetic checks."""
import json
from pathlib import Path
FIXTURE = Path(__file__).resolve().parents[1] / "examples/v0.6/blade-authorization-cases.json"
def errors(s):
    v=[]
    if s["attacker_has_authority"]: v.append("attacker_authority")
    if s["execution_requested"] and not s["authorized"]: v.append("unauthorized_execution")
    if s["operation"]=="replace_blade" and s["execution_requested"]:
        for field in ("authorized","independent_approval","old_lease_revoked","replacement_signed","scope_within_old","trace_verified","recovery_reviewed","post_swap_health","recovery_authorized"):
            if not s[field]: v.append(field)
        if not s["approver"] or s["approver"]==s["requester"]: v.append("independent_approver")
        if s["new_blade"]==s["old_blade"]: v.append("replacement_identity")
    return v
def main():
    data=json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert data["version"]=="0.6.0" and len(data["cases"])==20
    matched=0
    for c in data["cases"]:
        state={**data["defaults"],**c["changes"]}
        violations=errors(state)
        result="FAIL" if violations else "PASS"
        ok=result==c["expected"]
        print(f"{'MATCH' if ok else 'MISMATCH'} {c['id']} expected={c['expected']} actual={result} violations={','.join(violations) or '-'}")
        matched+=ok
    print(f"Matched {matched}/{len(data['cases'])}")
    return int(matched!=len(data["cases"]))
if __name__=="__main__": raise SystemExit(main())
