#!/usr/bin/env python3
"""
scripts/ci/audit_pr_diff.py
=============================================================================
DevSecOps Reviewer: Automated PR Diff Audit against Well-Architected guardrails.
Inspects added code in IaC, infrastructure definitions, and shell scripts.
Excludes documentation (*.md) and CI workflows (.github/workflows/).
=============================================================================
"""

import subprocess
import sys


def audit_diff(base_ref: str = "main") -> tuple[list[str], str]:
    diff_cmd = ["git", "diff", f"origin/{base_ref}...HEAD"]
    res = subprocess.run(diff_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        # Fallback to local ref if origin/ is not available
        diff_cmd = ["git", "diff", f"{base_ref}...HEAD"]
        res = subprocess.run(diff_cmd, capture_output=True, text=True)

    flags = []
    if res.returncode != 0:
        err_msg = res.stderr.strip() or "git diff exited with non-zero status"
        flags.append(f"❌ Git diff command failed against '{base_ref}': {err_msg}")
        summary = (
            "### 🛡️ DevSecOps Reviewer: Automated Heuristic Diff Screen\n\n"
            "**Verdict:** ⚠️ Needs Human Review - Diff Inspection Failed\n\n"
            f"**Flags Raised:**\n- {flags[0]}\n\n"
            "> *Notice: Git diff inspection failed to execute cleanly. Fail-closed: Human review required.*\n"
        )
        return flags, summary

    diff = res.stdout
    current_file = ""

    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            current_file = parts[2][2:] if len(parts) > 2 else ""
        elif line.startswith("+") and not line.startswith("+++"):
            # Exclude documentation, markdown checklists, and CI workflow configurations
            if current_file.endswith(".md") or current_file.startswith(".github/"):
                continue
            # Exclude Python test suites, regression runners, and audit harnesses
            if current_file.endswith(".py") and (
                "test" in current_file.lower()
                or "audit" in current_file.lower()
                or "regression" in current_file.lower()
            ):
                continue

            stripped = line[1:].strip()
            # Skip code comments
            if stripped.startswith(("#", "//", "/*", "*")):
                continue

            # Check for real IaC traps and security risks in code
            if "force_destroy = true" in stripped.lower() or "forces replacement" in stripped.lower():
                flags.append(f"⚠️ Potential state destruction or force replacement detected in `{current_file}`: `{stripped[:60]}`")
            if "0.0.0.0/0" in stripped and ("ingress" in stripped.lower() or "cidr_blocks" in stripped.lower()):
                flags.append(f"🚨 Open ingress to 0.0.0.0/0 detected in `{current_file}`: `{stripped[:60]}`")
            if "chmod 777" in stripped:
                flags.append(f"🚨 Permissive chmod 777 detected in `{current_file}`: `{stripped[:60]}`")

    summary = "### 🛡️ DevSecOps Reviewer: Automated Heuristic Diff Screen\n\n"
    summary += "**Verdict:** " + ("⚠️ Needs Human Review - Heuristic Flags Raised" if flags else "✅ Screen Passed - No Literal High-Risk Patterns Found") + "\n\n"
    if flags:
        summary += "**Flags Raised:**\n" + "\n".join(f"- {f}" for f in flags) + "\n"
    else:
        summary += "- No literal string matches found for targeted high-risk patterns (`force_destroy = true`, `forces replacement`, `0.0.0.0/0` ingress, `chmod 777`).\n"
        summary += "- *Notice: This is an automated heuristic diff screen, not a dynamic Terraform plan execution or semantic IAM analysis. Formal security review by a human maintainer remains required.*\n"

    return flags, summary


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "main"
    flags, summary = audit_diff(base)
    with open("pr_review.md", "w", encoding="utf-8") as f:
        f.write(summary)
    with open("pr_verdict.txt", "w", encoding="utf-8") as f:
        f.write("NEEDS_REVIEW" if flags else "CLEAN")
    print(summary)
    sys.exit(0)
