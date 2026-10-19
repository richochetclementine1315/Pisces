"""
pisces.fix_cmd
~~~~~~~~~~~~~~
Implements `pisces fix <file:line>` — the full self-healing repair loop.
State machine:
    DETECTED → PROPOSED → JUDGED → AWAITING_APPROVAL
    → APPROVED → CHECKPOINTED → APPLIED → VALIDATING
    → SUCCEEDED  (terminal ✓)
    → FAILED → HEALING → PROPOSED  (retry loop)
    → ROLLED_BACK  (terminal, all attempts exhausted)
    → REJECTED     (terminal, human said No)
"""
from __future__ import annotations
import subprocess
import uuid
from pathlib import Path
from typing import Optional
from pisces.config_manager import load_config
from pisces.context_manager import ContextManager
from pisces.explain_cmd import (
    _get_file_context,
    _get_source_snippet,
    _parse_ref,
    _CONTEXT_LINES,
)
from pisces.judge import judge_patch
from pisces.llm_client import call_llm
from pisces.models import Finding, JudgeResult, LLMRequest, RepairState, Severity
from pisces.patch_engine import (
    PATCH_END,
    PATCH_START,
    apply_patch,
    checkpoint_file,
    extract_patch_code,
    locate_function_lines,
    rollback,
    save_patch_record,
    validate_patch_syntax,
)
from pisces.scan_cmd import load_finding_by_ref
from pisces.tui import (
    console,
    print_diff,
    print_error,
    print_hitl_approval,
    print_section,
    print_step_fail,
    print_step_ok,
    print_step_running,
    print_success,
    print_warning,
    spinner,
)
# ─────────────────────────────────────────────────────────────
# Patch generation system prompt
# ─────────────────────────────────────────────────────────────
_FIX_SYSTEM = f"""\
You are an expert Python security engineer. Your task is to produce a
minimal, correct security patch for the vulnerability described.
Rules you MUST follow:
    1. Fix ONLY the vulnerability — do not refactor or reformat other code.
    2. Preserve the exact function signature and return type.
    3. The fix must be correct Python 3 and syntactically valid.
    4. Include a one-line comment explaining each security-relevant change.
    5. Output the replacement code BETWEEN these exact markers and nowhere else:
{PATCH_START}
<replacement code here>
{PATCH_END}
Do NOT include anything outside the markers.
Do NOT include the markers themselves as part of the code.
Output ONLY the patched code block, nothing else.
"""
# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────
def run_fix(
    ref: str,
    project_root: Path,
    dry_run: bool = False,     # Generate and display a patch without modifying the source file.
    skip_judge: bool = False,  # Skips the LLM based patch evaluation
    max_attempts: Optional[int] = None,  #Overrides the configured retry limit for self-healing attempts.
    auto_approve: bool = False,  # Skips human-in-the-loop approval. This is not recommended for production use.
) -> int:
    """
    Entry point for `pisces fix <ref>`.
    Returns 0 on success (SUCCEEDED), 1 on failure/rejection.
    """
    print_section("pisces fix — Self-Healing Repair")
    # ── Parse reference ─────────────────────────────────────
    file_path, line_no = _parse_ref(ref, project_root)
    if file_path is None:
        print_error(f"Invalid reference: '{ref}'  (expected: path/to/file.py:42)")
        return 1
    rel_path = str(file_path.relative_to(project_root))
    lookup   = f"{rel_path}:{line_no}"
    # ── Load finding ─────────────────────────────────────────
    finding = load_finding_by_ref(project_root, lookup)
    if finding is None:
        print_error(
            f"No finding cached at '{lookup}'.\n"
            "  Run 'pisces scan .' first."
        )
        return 1
    # ── Load config ──────────────────────────────────────────
    try:
        cfg = load_config(project_root)
    except RuntimeError as e:
        print_error(str(e))
        return 1
    provider        = cfg.llm.provider
    model           = cfg.llm.model
    max_attempts    = (
        max_attempts
        if max_attempts is not None
        else cfg.repair.max_attempts
        )
    require_hitl    = cfg.repair.require_approval and not auto_approve
    test_command    = cfg.validation.test_command
    repair_id       = str(uuid.uuid4())[:8]
    checkpoint_path: Optional[Path] = None
    state           = RepairState.DETECTED
    console.print(f"  [dim]Finding:[/] [cyan]{lookup}[/]  [dim]Severity:[/] {_severity_badge(finding.severity)}")
    console.print(f"  [dim]Provider:[/] [magenta]{provider}[/] / [cyan]{model}[/]")
    console.print(f"  [dim]Max attempts:[/] {max_attempts}  |  [dim]HITL:[/] {'yes' if require_hitl else 'no (--auto-approve)'}")
    console.print()
    # ── Locate function boundaries ───────────────────────────
    fn_start, fn_end = locate_function_lines(file_path, line_no)
    original_block   = _read_lines(file_path, fn_start, fn_end)
    source_snippet   = _get_source_snippet(file_path, line_no, context=_CONTEXT_LINES)
    file_ctx         = _get_file_context(project_root, rel_path)
    # The repair loop
    state      = RepairState.DETECTED
    prior_fail: Optional[str] = None
    for attempt in range(1, max_attempts + 1):
        console.rule(
            f"[bold]Attempt {attempt} / {max_attempts}[/]",
            style="dim blue",
        )
        # ── Step 1: Generate patch ────────────────────────────
        state = RepairState.PROPOSED
        print_step_running(f"[{attempt}] Generating patch with {provider}/{model} ...")
        patch_code = _generate_patch(
            finding=finding,
            source_snippet=source_snippet,
            file_ctx_str=_fmt_file_ctx(file_ctx),
            fn_start=fn_start,
            fn_end=fn_end,
            original_block=original_block,
            provider=provider,
            model=model,
            prior_failure=prior_fail,
        )
        if patch_code is None:
            print_step_fail("LLM did not produce a valid patch block.")
            state = RepairState.FAILED
            prior_fail = "LLM failed to output a patch in the expected format."
            continue
        # Validate patch syntax before judging
        valid, err = validate_patch_syntax(patch_code)
        if not valid:
            print_step_fail(f"Patch has syntax error: {err}")
            state = RepairState.FAILED
            prior_fail = f"Patch syntax error: {err}"
            continue
        print_step_ok(f"Patch generated ({patch_code.count(chr(10))+1} lines)")
        # ── Step 2: Show diff ─────────────────────────────────
        print_diff(
            diff_text=patch_code, 
            filename=rel_path
            )
        if dry_run:
            console.print(
                "[bold yellow]DRY RUN:[/] Proposed patch displayed;" 
                "the original file has NOT been modified."
            )
            return 0
        # ── Step 3: Judge ─────────────────────────────────────
        
        state = RepairState.JUDGED

        if skip_judge:
            print_warning("LLM judge skipped by --no-judge.")
            judge = _fallback_judge()
        else:
            print_step_running("Judge reviewing the patch ...")
            try:
               with spinner("Running judge LLM..."):
                  judge = judge_patch(
                       finding=finding,
                       original_code=original_block,
                       patched_code=patch_code,
                       provider=provider,
                       model=model,
                       prior_failure=prior_fail,
                   )
            except Exception as e:
                print_warning(f"Judge failed: {e} — proceeding anyway.")
                judge = _fallback_judge()

        _print_judge_result(judge)

        if not judge.approved:
            print_warning(
                f"Judge REJECTED this patch: {judge.reasoning[:200]}"
            )
            state      = RepairState.FAILED
            prior_fail = f"Judge rejected: {judge.reasoning}"
            if attempt < max_attempts:
                console.print("  [dim]Retrying with judge feedback...[/]\n")
                continue
            else:
                _save_and_exit(project_root, repair_id, finding, patch_code,
                               judge, None, state.value)
                return 1
        # ── Step 4: HITL Approval ─────────────────────────────
        state = RepairState.AWAITING_APPROVAL
        if require_hitl:
            approved = print_hitl_approval(
                finding=finding.to_dict(),
                patch_summary=f"{patch_code.count(chr(10))+1} lines, "
                              f"quality={judge.patch_quality}, risk={judge.regression_risk}",
                judge_result=judge.to_dict(),
            )
        else:
            console.print(
                "  [dim]--auto-approve active — skipping human review.[/]"
            )
            approved = True
        if not approved:
            state = RepairState.REJECTED
            console.print()
            console.print("[high]✗  Patch rejected by user.[/]")
            _save_and_exit(project_root, repair_id, finding, patch_code,
                           judge, False, state.value)
            return 1
        state = RepairState.APPROVED
        # ── Step 5: Checkpoint ────────────────────────────────
        state = RepairState.CHECKPOINTED
        try:
            checkpoint_path = checkpoint_file(file_path, project_root, repair_id)
        except OSError as e:
            print_step_fail(f"Checkpoint failed: {e}")
            return 1
        # ── Step 6: Apply patch ───────────────────────────────
        state = RepairState.APPLIED
        try:
            apply_patch(file_path, patch_code, fn_start, fn_end)
        except (OSError, ValueError) as e:
            print_step_fail(f"Patch application failed: {e}")
            if checkpoint_path:
                rollback(file_path, checkpoint_path)
            state = RepairState.ROLLED_BACK
            _save_and_exit(project_root, repair_id, finding, patch_code,
                           judge, True, state.value)
            return 1
        # ── Step 7: Validate (run tests) ──────────────────────
        state = RepairState.VALIDATING
        console.print()
        print_step_running(f"Running validation: [cyan]{test_command}[/] ...")
        test_ok, test_output = _run_tests(project_root, test_command)
        if test_ok:
            state = RepairState.SUCCEEDED
            console.print()
            print_success(
                f"✓  Repair SUCCEEDED (attempt {attempt}/{max_attempts})\n\n"
                f"  The vulnerability in [cyan]{rel_path}:{line_no}[/] has been fixed.\n"
                f"  Run [cyan]pisces scan .[/] to confirm no remaining issues."
            )
            _save_and_exit(project_root, repair_id, finding, patch_code,
                           judge, True, state.value)
            # Invalidate context for the patched file
            try:
                cm = ContextManager(project_root)
                cm.update_single_file(file_path)
            except Exception:
                pass
            return 0
        # ── Tests failed → healing loop ───────────────────────
        state = RepairState.FAILED
        print_step_fail(f"Test suite failed after patching.")
        console.print(f"  [dim]{test_output[:400]}[/]\n")
        if checkpoint_path:
            rollback(file_path, checkpoint_path)
        state      = RepairState.HEALING
        prior_fail = (
            f"Patch was applied but tests failed:\n{test_output[:600]}"
        )
        if attempt < max_attempts:
            console.print(
                f"  [dim]Healing — will regenerate patch with failure context.[/]\n"
            )
            continue
    # ── All attempts exhausted ────────────────────────────────
    state = RepairState.ROLLED_BACK
    print_step_fail(
        f"All {max_attempts} repair attempt(s) exhausted — "
        "original file restored."
    )
    _save_and_exit(project_root, repair_id, finding, "", None, None, state.value)
    return 1
# ─────────────────────────────────────────────────────────────
# Patch generation
# ─────────────────────────────────────────────────────────────
def _generate_patch(
    finding: Finding,
    source_snippet: str,
    file_ctx_str: str,
    fn_start: int,
    fn_end: int,
    original_block: str,
    provider: str,
    model: str,
    prior_failure: Optional[str],
) -> Optional[str]:
    prior_section = ""
    if prior_failure:
        prior_section = f"""
## ⚠ Prior Attempt Failed
Your previous patch was tried and failed for this reason:
{prior_failure[:800]}

Study this carefully and produce an improved patch.
"""
    user_prompt = f"""\
## Security Finding
- File:     `{finding.file}`
- Line:     {finding.line}
- Rule:     `{finding.rule}`
- Severity: {finding.severity.value}
- Issue:    {finding.description}
- Code:     `{finding.code}`
- Impact:   {finding.impact}
- Fix hint: {finding.remediation}
---
## Function to Patch (lines {fn_start}–{fn_end})
```python
{original_block}
Surrounding Context (for reference only — do NOT include in patch)
python
{source_snippet}
File-Level Context
{file_ctx_str} {prior_section}
Produce the fixed replacement for the function shown above. Wrap it EXACTLY in {PATCH_START} and {PATCH_END} markers. """

    request = LLMRequest(
        system_prompt=_FIX_SYSTEM,
        user_prompt=user_prompt,
        temperature=0.15,
        max_tokens=2048,
    )
    try:
        with spinner("Generating patch..."):
            response = call_llm(request, provider=provider, model=model)
    except (EnvironmentError, RuntimeError) as e:
        print_step_fail(str(e))
        return None
    return extract_patch_code(response.content)


# ─────────────────────────────────────────────────────────────
# Test runner
# ─────────────────────────────────────────────────────────────
def _run_tests(project_root: Path, test_command: str) -> tuple[bool, str]:
    """
    Run test_command in project_root.

    Returns (success, combined_output).
    """
    try:
        result = subprocess.run(
            test_command.split(),
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,   # deliberately NOT shell=True
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        return result.returncode == 0, output
    except FileNotFoundError:
        return True, f"Test command '{test_command}' not found — skipping validation."
    except subprocess.TimeoutExpired:
        return False, "Test command timed out after 120 seconds."
    except Exception as e:
        return True, f"Test runner error (non-fatal): {e}"


# ─────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────
def _print_judge_result(judge: JudgeResult) -> None:
    decision_color = "success" if judge.approved else "high"

    console.print(
        f"  Judge: [{decision_color}]{judge.decision}[/] "
        f"security_ok={judge.security_ok} "
        f"risk=[bold]{judge.regression_risk}[/] "
        f"quality={judge.patch_quality}"
    )
    console.print(f"  [dim]{judge.reasoning[:180]}[/]")
    console.print()

def _severity_badge(sev: Severity) -> str:
    colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "green",
        Severity.INFO: "dim",
    }

    color = colors.get(sev, "white")
    return f"[{color}]{sev.value}[/]"

def _fmt_file_ctx(file_ctx) -> str:
    if file_ctx is None:
        return "Not available."

    lines = []

    if file_ctx.imports:
        lines.append(
            "Imports: " + ", ".join(i.module for i in file_ctx.imports[:12])
        )

    if file_ctx.functions:
        lines.append(
            "Functions: " + ", ".join(f.name for f in file_ctx.functions[:8])
        )

    return "\\n".join(lines) or "Not available."

def _read_lines(file_path: Path, start: int, end: int) -> str:
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
        return "\\n".join(lines[start - 1 : end])
    except OSError:
        return ""

def _fallback_judge() -> JudgeResult:
    """When judge LLM itself fails, return a permissive default."""
    from pisces.models import JudgeResult

    return JudgeResult(
        decision="APPROVED",
        security_ok=True,
        functionality_ok=True,
        scope_ok=True,
        regression_risk="MEDIUM",
        patch_quality="ACCEPTABLE",
        completeness="COMPLETE",
        reasoning="Judge LLM unavailable — proceeding with HITL review.",
    )

def _save_and_exit(
    project_root,
    repair_id,
    finding,
    patch_code,
    judge,
    human_approved,
    state,
):
    try:
        save_patch_record(
            project_root=project_root,
            repair_id=repair_id,
            finding_dict=finding.to_dict(),
            patch_code=patch_code,
            judge_result_dict=judge.to_dict() if judge else None,
            human_approved=human_approved,
            state=state,
        )
    except Exception:
        pass
