"""
pisces.judge
~~~~~~~~~~~~
LLM-based code review judge for proposed security patches.

The judge acts as an adversarial reviewer:
    "Does this patch CORRECTLY and COMPLETELY fix the vulnerability
     without introducing new problems or changing unrelated behaviour?"

Returns a structured JudgeResult the repair loop uses to decide
whether to accept the patch, reject it, or ask for another attempt.
"""
from __future__ import annotations

import re
from typing import Optional

from pisces.llm_client import call_llm
from pisces.models import Finding, JudgeResult, LLMRequest

_JUDGE_SYSTEM = """\
You are an adversarial security code reviewer. Your job is to judge
whether a proposed patch correctly fixes a security vulnerability.
Be strict. Reject patches that are incomplete, introduce new issues,
or change behaviour unrelated to the vulnerability.

Respond ONLY in this exact format:

DECISION: APPROVED
SECURITY_OK: true
FUNCTIONALITY_OK: true
SCOPE_OK: true
REGRESSION_RISK: LOW
PATCH_QUALITY: GOOD
COMPLETENESS: COMPLETE
REASONING: <one paragraph>

Valid values:
  DECISION:         APPROVED | REJECTED
  SECURITY_OK:      true | false   (does it fix the vulnerability?)
  FUNCTIONALITY_OK: true | false   (does it preserve intended behaviour?)
  SCOPE_OK:         true | false   (does it change ONLY what's needed?)
  REGRESSION_RISK:  LOW | MEDIUM | HIGH
  PATCH_QUALITY:    GOOD | ACCEPTABLE | POOR
  COMPLETENESS:     COMPLETE | PARTIAL | INCOMPLETE
"""


def judge_patch(
    finding: Finding,
    original_code: str,
    patched_code: str,
    provider: str,
    model: str,
    prior_failure: Optional[str] = None,
) -> JudgeResult:
    """
    Ask the LLM to judge whether *patched_code* correctly fixes *finding*.

    *prior_failure* — if this is a re-attempt after test failure, include
    the test output so the judge has extra context.
    """
    prior_section = ""
    if prior_failure:
        prior_section = f"""
## Prior Attempt Failed
The patch was applied and tests were run. The test suite FAILED with:
{prior_failure[:1000]}

Consider whether the patch caused this failure.
"""
    user_prompt = f"""\
## Security Finding to Fix
- Rule:     {finding.rule}
- Severity: {finding.severity.value}
- File:     {finding.file}
- Line:     {finding.line}
- Issue:    {finding.description}
- Code:     `{finding.code}`
---
## Original Code (vulnerable)
```python
{original_code}
Proposed Patch
python
{patched_code}
{prior_section}
Judge this patch. Is it correct, complete, and safe to apply? """

    request = LLMRequest(
        system_prompt=_JUDGE_SYSTEM,
        user_prompt=user_prompt,
        temperature=0.1,    # very low — we want consistent, strict judgment
        max_tokens=512,
    )
    response = call_llm(request, provider=provider, model=model)
    return _parse_judge_response(response.content)


def _parse_judge_response(content: str) -> JudgeResult:
    """Parse the structured judge response into a JudgeResult."""

    def _field(name: str, default: str = "") -> str:
        m = re.search(rf"^{name}:\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else default

    def _bool_field(name: str, default: bool = True) -> bool:
        val = _field(name, "true").lower()
        return val == "true"

    decision = _field("DECISION", "REJECTED").upper()
    security_ok = _bool_field("SECURITY_OK", False)
    functionality_ok = _bool_field("FUNCTIONALITY_OK", True)
    scope_ok = _bool_field("SCOPE_OK", True)
    regression_risk = _field("REGRESSION_RISK", "MEDIUM").upper()
    patch_quality = _field("PATCH_QUALITY", "ACCEPTABLE").upper()
    completeness = _field("COMPLETENESS", "PARTIAL").upper()
    reasoning = _field("REASONING", content[:300])
    # Safety override: if security not fixed, decision must be REJECTED
    if not security_ok:
        decision = "REJECTED"
    return JudgeResult(
        decision=decision,
        security_ok=security_ok,
        functionality_ok=functionality_ok,
        scope_ok=scope_ok,
        regression_risk=regression_risk,
        patch_quality=patch_quality,
        completeness=completeness,
        reasoning=reasoning,
    )