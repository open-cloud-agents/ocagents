"""Open Policy Agent (Rego) Policy Evaluator Integration.

Evaluates Terraform plans and Kubernetes manifests against institutional security
and reliability policies (Rule 01: Destructive Actions, Rule 04: Well-Architected Invariants).
Integrates both the external 'opa' CLI binary (when present) and a built-in zero-dependency
institutional policy evaluator for maximum portability.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any

from ocagents.findings.normalizer import (
    CANONICAL_SCHEMA_URI,
    RULE_DESTRUCTIVE,
    RULE_TO_DEFAULT_RECOMMENDATION,
    RULE_WELL_ARCHITECTED,
    clean_artifact_uri,
    compute_finding_id,
    map_category,
)
from ocagents.findings.provenance import resolve_default_repo_root
from ocagents.scanner.diff_filter import HUNK_HEADER_PATTERN, filter_findings_by_diff

DEFAULT_POLICIES_DIR = Path(__file__).resolve().parent / "policies"
ROOT_POLICIES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "policies" / "rego"

STATEFUL_RESOURCE_PREFIXES = (
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_s3_bucket",
    "google_sql_database_instance",
    "google_storage_bucket",
    "azurerm_mssql_database",
    "azurerm_storage_account",
    "kubernetes_persistent_volume",
)

K8S_WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "Job", "Pod"})


def _parse_scalar(val: str) -> Any:
    """Parses a YAML scalar value into a typed Python object."""
    val = val.strip()
    val_lower = val.lower()
    if val_lower in ("null", "none", "~"):
        return None
    if val_lower == "true":
        return True
    if val_lower == "false":
        return False
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val.strip('"\'')


def parse_manifest_documents(content: str) -> list[dict[str, Any]]:
    """Parses single- or multi-document JSON/YAML Kubernetes manifests."""
    # 1. Fast path: JSON payload
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return [parsed]
        if isinstance(parsed, list):
            return [doc for doc in parsed if isinstance(doc, dict)]
    except Exception:
        pass

    # 2. Multi-document YAML splitting
    docs: list[dict[str, Any]] = []
    chunks = content.split("\n---")
    for chunk in chunks:
        lines: list[tuple[int, str]] = []
        for raw in chunk.splitlines():
            l = raw
            if "#" in l:
                l = l.split("#")[0]
            if l.strip():
                indent = len(l) - len(l.lstrip())
                lines.append((indent, l.strip()))
        if not lines:
            continue

        def parse_block(i: int, min_indent: int) -> tuple[Any, int]:
            if i >= len(lines):
                return None, i

            first_indent, first_text = lines[i]
            if first_indent < min_indent:
                return None, i

            if first_text.startswith("- "):
                res_list: list[Any] = []
                while i < len(lines):
                    ind, txt = lines[i]
                    if ind < min_indent:
                        break
                    if txt.startswith("- "):
                        content_str = txt[2:].strip()
                        if ":" in content_str:
                            k, v = content_str.split(":", 1)
                            k, v = k.strip(), v.strip()
                            item_dict: dict[str, Any] = {}
                            if v:
                                item_dict[k] = _parse_scalar(v)
                                i += 1
                            else:
                                child, i = parse_block(i + 1, ind + 1)
                                item_dict[k] = child if child is not None else {}

                            while i < len(lines):
                                s_ind, s_txt = lines[i]
                                if s_ind <= ind:
                                    break
                                if ":" in s_txt:
                                    sk, sv = s_txt.split(":", 1)
                                    sk, sv = sk.strip(), sv.strip()
                                    if sv:
                                        item_dict[sk] = _parse_scalar(sv)
                                        i += 1
                                    else:
                                        child, i = parse_block(i + 1, s_ind + 1)
                                        item_dict[sk] = child if child is not None else {}
                                else:
                                    i += 1
                            res_list.append(item_dict)
                        else:
                            res_list.append(_parse_scalar(content_str))
                            i += 1
                    else:
                        break
                return res_list, i
            else:
                res_dict: dict[str, Any] = {}
                while i < len(lines):
                    ind, txt = lines[i]
                    if ind < min_indent:
                        break
                    if ":" in txt:
                        k, v = txt.split(":", 1)
                        k, v = k.strip(), v.strip()
                        if v:
                            res_dict[k] = _parse_scalar(v)
                            i += 1
                        else:
                            child, i = parse_block(i + 1, ind + 1)
                            res_dict[k] = child if child is not None else {}
                    else:
                        i += 1
                return res_dict, i

        parsed_doc, _ = parse_block(0, 0)
        if isinstance(parsed_doc, dict):
            docs.append(parsed_doc)
        elif isinstance(parsed_doc, list):
            for d in parsed_doc:
                if isinstance(d, dict):
                    docs.append(d)

    return docs


class OpaEvaluator:
    """Evaluates Terraform plans and Kubernetes manifests against institutional policies."""

    def __init__(
        self,
        repo_root: Path | None = None,
        policy_dir: Path | None = None,
        default_agent: str = "opa",
        evidence_scheme: str = "repo",
        use_cli_if_available: bool = True,
    ) -> None:
        self.repo_root = (repo_root or resolve_default_repo_root()).resolve()
        self.policy_dir = (
            Path(policy_dir).resolve()
            if policy_dir
            else (
                ROOT_POLICIES_DIR if ROOT_POLICIES_DIR.is_dir() else DEFAULT_POLICIES_DIR
            )
        )
        self.default_agent = default_agent
        self.evidence_scheme = evidence_scheme if evidence_scheme in {"repo", "diff"} else "repo"
        self.use_cli_if_available = use_cli_if_available
        self._opa_cli = shutil.which("opa") if use_cli_if_available else None

    @property
    def has_opa_cli(self) -> bool:
        """Indicates whether native 'opa' CLI binary is installed and active."""
        return self._opa_cli is not None

    def evaluate_terraform_plan(
        self,
        plan_input: dict[str, Any] | str | Path,
        target_file: str = "infra/main.tf",
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluates a Terraform plan against institutional destruction and well-architected policies."""
        plan_dict = self._load_json(plan_input)
        clean_file = clean_artifact_uri(target_file, repo_root=self.repo_root)

        findings: list[dict[str, Any]] = []
        if self.has_opa_cli and self.policy_dir.is_dir():
            try:
                findings = self._evaluate_via_opa_cli(plan_dict, target_file=clean_file, diff_text=diff_text)
            except Exception:
                findings = []

        if not findings:
            findings = self._evaluate_terraform_builtin(plan_dict, target_file=clean_file, diff_text=diff_text)

        if diff_text:
            findings = filter_findings_by_diff(
                findings,
                diff_text,
                convert_to_diff_scheme=(self.evidence_scheme == "diff"),
            )

        return findings

    def evaluate_kubernetes_manifest(
        self,
        manifest_input: dict[str, Any] | list[dict[str, Any]] | str | Path,
        target_file: str = "k8s/deployment.yaml",
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluates Kubernetes workload manifests against institutional reliability and security guardrails."""
        docs = self._load_manifest_docs(manifest_input)
        clean_file = clean_artifact_uri(target_file, repo_root=self.repo_root)

        findings: list[dict[str, Any]] = []
        for doc in docs:
            doc_findings: list[dict[str, Any]] = []
            if self.has_opa_cli and self.policy_dir.is_dir():
                try:
                    doc_findings = self._evaluate_via_opa_cli(doc, target_file=clean_file, diff_text=diff_text)
                except Exception:
                    doc_findings = []

            if not doc_findings:
                doc_findings = self._evaluate_k8s_doc_builtin(doc, target_file=clean_file, diff_text=diff_text)

            findings.extend(doc_findings)

        if diff_text:
            findings = filter_findings_by_diff(
                findings,
                diff_text,
                convert_to_diff_scheme=(self.evidence_scheme == "diff"),
            )

        return findings

    def evaluate_file(
        self,
        file_path: str | Path,
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluates a single file, automatically detecting whether it is a Terraform plan or K8s manifest."""
        p = Path(file_path)
        if not p.is_file():
            raise FileNotFoundError(f"Target file for policy evaluation not found: '{p}'")

        content = p.read_text(encoding="utf-8", errors="replace")
        clean_target = clean_artifact_uri(p.as_posix(), repo_root=self.repo_root)

        # 1. Try parsing as JSON to detect Terraform plan
        try:
            parsed_json = json.loads(content)
            if isinstance(parsed_json, dict) and (
                "resource_changes" in parsed_json or "terraform_version" in parsed_json
            ):
                return self.evaluate_terraform_plan(parsed_json, target_file=clean_target, diff_text=diff_text)
        except Exception:
            pass

        # 2. Raw Terraform HCL / Bicep source is handled by Checkov/Trivy linters
        if p.suffix.lower() in {".tf", ".tfvars", ".bicep"}:
            return []

        # 3. Evaluate as Kubernetes / IaC manifest
        return self.evaluate_kubernetes_manifest(content, target_file=clean_target, diff_text=diff_text)

    def _evaluate_via_opa_cli(
        self,
        payload: dict[str, Any],
        target_file: str,
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Executes external OPA CLI binary with Rego policies and normalizes findings."""
        if not self._opa_cli or not self.policy_dir.is_dir():
            return []

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(payload, tmp)
            tmp_path = Path(tmp.name)

        try:
            cmd = [
                self._opa_cli,
                "eval",
                "--format",
                "json",
                "--data",
                str(self.policy_dir),
                "--input",
                str(tmp_path),
                "data.open_cloud_agents",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                return []

            result_data = json.loads(proc.stdout)
            results = result_data.get("result", [])
            if not results:
                return []

            expressions = results[0].get("expressions", [])
            if not expressions:
                return []

            pkg_root = expressions[0].get("value", {})
            findings: list[dict[str, Any]] = []

            for pkg_name, pkg_data in pkg_root.items():
                if not isinstance(pkg_data, dict):
                    continue
                violations = pkg_data.get("violations", [])
                if not isinstance(violations, list):
                    continue

                for v in violations:
                    if not isinstance(v, dict):
                        continue
                    rule_id = v.get("rule_id", RULE_WELL_ARCHITECTED)
                    severity = v.get("severity", "high")
                    resource = v.get("resource", "unknown_resource")
                    fact = v.get("title", v.get("fact", "Policy violation detected"))
                    recommendation = v.get("recommendation", "")

                    attr_keyword = self._infer_attribute_keyword(fact, rule_id)
                    line_start, line_end, is_resolved = self._locate_source_span(
                        target_file,
                        res_address=resource,
                        attr_keyword=attr_keyword,
                        diff_text=diff_text,
                    )

                    f = self._build_finding(
                        rule_id=rule_id,
                        severity=severity,
                        resource=resource,
                        fact=fact,
                        recommendation=recommendation,
                        target_file=target_file,
                        line_start=line_start,
                        line_end=line_end,
                        line_resolved=is_resolved,
                        evaluator_engine="opa_cli",
                        metadata={"rego_package": pkg_name, "raw_violation": v},
                    )
                    findings.append(f)

            return findings
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def _evaluate_terraform_builtin(
        self,
        plan: dict[str, Any],
        target_file: str,
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Pure-Python institutional evaluator for Terraform plan structures."""
        findings: list[dict[str, Any]] = []
        resource_changes = plan.get("resource_changes", [])
        if not isinstance(resource_changes, list):
            return []

        for rc in resource_changes:
            if not isinstance(rc, dict):
                continue
            res_type = rc.get("type", "unknown_type")
            res_address = rc.get("address", res_type)
            change = rc.get("change", {})
            actions = change.get("actions", [])
            after = change.get("after") or {}

            # Rule 01: Resource Deletion in Terraform Plan
            if "delete" in actions and "create" not in actions:
                line_start, line_end, is_resolved = self._locate_source_span(
                    target_file,
                    res_address=res_address,
                    diff_text=diff_text,
                )
                f = self._build_finding(
                    rule_id=RULE_DESTRUCTIVE,
                    severity="critical",
                    resource=res_address,
                    fact=f"Resource '{res_address}' ({res_type}) is scheduled for deletion.",
                    recommendation=(
                        "Destructive deletions require human confirmation. "
                        "Configure lifecycle prevent_destroy guardrails."
                    ),
                    target_file=target_file,
                    line_start=line_start,
                    line_end=line_end,
                    line_resolved=is_resolved,
                    evaluator_engine="builtin_rego_engine",
                    metadata={"actions": actions, "type": res_type},
                )
                findings.append(f)

            # Rule 01: Stateful Resource Forced Replacement (Delete + Create)
            if "delete" in actions and "create" in actions:
                is_stateful = any(res_type.startswith(p) for p in STATEFUL_RESOURCE_PREFIXES)
                if is_stateful:
                    line_start, line_end, is_resolved = self._locate_source_span(
                        target_file,
                        res_address=res_address,
                        diff_text=diff_text,
                    )
                    f = self._build_finding(
                        rule_id=RULE_DESTRUCTIVE,
                        severity="critical",
                        resource=res_address,
                        fact=f"Stateful resource '{res_address}' ({res_type}) triggers forced replacement (destroy and recreate).",
                        recommendation=(
                            "Forced replacement will destroy existing persistent data. "
                            "Migrate resource in-place or isolate changes to non-destructive attributes."
                        ),
                        target_file=target_file,
                        line_start=line_start,
                        line_end=line_end,
                        line_resolved=is_resolved,
                        evaluator_engine="builtin_rego_engine",
                        metadata={"actions": actions, "type": res_type, "forced_replacement": True},
                    )
                    findings.append(f)

            # Rule 01: force_destroy flag enabled
            if after.get("force_destroy") is True:
                line_start, line_end, is_resolved = self._locate_source_span(
                    target_file,
                    res_address=res_address,
                    attr_keyword="force_destroy",
                    diff_text=diff_text,
                )
                f = self._build_finding(
                    rule_id=RULE_DESTRUCTIVE,
                    severity="critical",
                    resource=res_address,
                    fact=f"Resource '{res_address}' enables force_destroy.",
                    recommendation="Disable force_destroy to prevent catastrophic automated data loss on bucket or cluster deletion.",
                    target_file=target_file,
                    line_start=line_start,
                    line_end=line_end,
                    line_resolved=is_resolved,
                    evaluator_engine="builtin_rego_engine",
                    metadata={"force_destroy": True},
                )
                findings.append(f)

            # Rule 04: S3 Bucket Missing Server-Side Encryption
            if res_type == "aws_s3_bucket":
                if not after.get("server_side_encryption_configuration"):
                    line_start, line_end, is_resolved = self._locate_source_span(
                        target_file,
                        res_address=res_address,
                        attr_keyword="server_side_encryption",
                        diff_text=diff_text,
                    )
                    f = self._build_finding(
                        rule_id=RULE_WELL_ARCHITECTED,
                        severity="high",
                        resource=res_address,
                        fact=f"S3 bucket '{res_address}' is missing server-side encryption configuration.",
                        recommendation="Configure server_side_encryption_configuration with KMS (aws:kms) to enforce encryption at rest.",
                        target_file=target_file,
                        line_start=line_start,
                        line_end=line_end,
                        line_resolved=is_resolved,
                        evaluator_engine="builtin_rego_engine",
                        metadata={"missing": "server_side_encryption_configuration"},
                    )
                    findings.append(f)

            # Rule 04: Relational Database Missing Multi-AZ
            if res_type in ("aws_db_instance", "aws_rds_cluster"):
                if after.get("multi_az") is not True:
                    line_start, line_end, is_resolved = self._locate_source_span(
                        target_file,
                        res_address=res_address,
                        attr_keyword="multi_az",
                        diff_text=diff_text,
                    )
                    f = self._build_finding(
                        rule_id=RULE_WELL_ARCHITECTED,
                        severity="high",
                        resource=res_address,
                        fact=f"Database '{res_address}' is not configured for Multi-AZ deployment (multi_az != true).",
                        recommendation="Set multi_az = true to satisfy high-availability and disaster recovery RTO/RPO requirements.",
                        target_file=target_file,
                        line_start=line_start,
                        line_end=line_end,
                        line_resolved=is_resolved,
                        evaluator_engine="builtin_rego_engine",
                        metadata={"missing": "multi_az"},
                    )
                    findings.append(f)

        return findings

    def _evaluate_k8s_doc_builtin(
        self,
        doc: dict[str, Any],
        target_file: str,
        diff_text: str | None = None,
    ) -> list[dict[str, Any]]:
        """Pure-Python institutional evaluator for Kubernetes manifest documents."""
        findings: list[dict[str, Any]] = []
        kind = doc.get("kind", "")
        if kind not in K8S_WORKLOAD_KINDS:
            return []

        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unnamed")
        resource_id = f"{kind.lower()}/{name}"

        spec = doc.get("spec", {})
        template = spec.get("template", {}) if "template" in spec else doc
        pod_spec = template.get("spec", {})
        containers = pod_spec.get("containers", [])
        if not isinstance(containers, list):
            return []

        for c in containers:
            if not isinstance(c, dict):
                continue
            c_name = c.get("name", "container")
            sec_ctx = c.get("securityContext", {})
            resources = c.get("resources", {})
            limits = resources.get("limits", {})
            readiness = c.get("readinessProbe")

            # Rule 04: Privileged container forbidden
            if sec_ctx.get("privileged") is True:
                line_start, line_end, is_resolved = self._locate_source_span(
                    target_file,
                    res_address=c_name,
                    attr_keyword="privileged",
                    diff_text=diff_text,
                )
                f = self._build_finding(
                    rule_id=RULE_WELL_ARCHITECTED,
                    severity="critical",
                    resource=resource_id,
                    fact=f"Container '{c_name}' in {kind} '{name}' is configured as privileged (securityContext.privileged = true).",
                    recommendation="Set securityContext.privileged = false to prevent host filesystem breakout and node compromise.",
                    target_file=target_file,
                    line_start=line_start,
                    line_end=line_end,
                    line_resolved=is_resolved,
                    evaluator_engine="builtin_rego_engine",
                    metadata={"container": c_name, "privileged": True},
                )
                findings.append(f)

            # Rule 04: Memory limits required for QoS and OOM protection
            if not limits.get("memory"):
                line_start, line_end, is_resolved = self._locate_source_span(
                    target_file,
                    res_address=c_name,
                    attr_keyword="memory",
                    diff_text=diff_text,
                )
                f = self._build_finding(
                    rule_id=RULE_WELL_ARCHITECTED,
                    severity="high",
                    resource=resource_id,
                    fact=f"Container '{c_name}' in {kind} '{name}' does not specify a memory limit (resources.limits.memory).",
                    recommendation="Specify resources.limits.memory matching requests.memory to guarantee QoS and avoid node OOM evictions.",
                    target_file=target_file,
                    line_start=line_start,
                    line_end=line_end,
                    line_resolved=is_resolved,
                    evaluator_engine="builtin_rego_engine",
                    metadata={"container": c_name, "missing": "resources.limits.memory"},
                )
                findings.append(f)

            # Rule 04: Readiness probe required for zero-downtime routing
            if not readiness:
                line_start, line_end, is_resolved = self._locate_source_span(
                    target_file,
                    res_address=c_name,
                    attr_keyword="readinessProbe",
                    diff_text=diff_text,
                )
                f = self._build_finding(
                    rule_id=RULE_WELL_ARCHITECTED,
                    severity="medium",
                    resource=resource_id,
                    fact=f"Container '{c_name}' in {kind} '{name}' has no readinessProbe defined.",
                    recommendation="Add readinessProbe to ensure traffic is only routed after application initialization and healthy dependency checks.",
                    target_file=target_file,
                    line_start=line_start,
                    line_end=line_end,
                    line_resolved=is_resolved,
                    evaluator_engine="builtin_rego_engine",
                    metadata={"container": c_name, "missing": "readinessProbe"},
                )
                findings.append(f)

        return findings

    def _build_finding(
        self,
        rule_id: str,
        severity: str,
        resource: str,
        fact: str,
        recommendation: str,
        target_file: str,
        line_start: int = 1,
        line_end: int = 1,
        line_resolved: bool = True,
        evaluator_engine: str = "builtin_rego_engine",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Constructs a finding conforming strictly to schemas/v1/finding.json."""
        if line_end > line_start:
            evidence = f"{self.evidence_scheme}:{target_file}#L{line_start}-L{line_end}"
        else:
            evidence = f"{self.evidence_scheme}:{target_file}#L{line_start}"

        fnd_id = compute_finding_id(
            rule_id=rule_id,
            resource=resource,
            evidence=evidence,
        )

        category = map_category(
            rule_id=rule_id,
            driver_name=self.default_agent,
        )

        full_meta: dict[str, Any] = {
            "policy_engine": "opa_rego",
            "evaluator": evaluator_engine,
            "line_resolved": line_resolved,
            "location_precision": "exact" if line_resolved else "file_level",
        }
        if metadata:
            full_meta.update(metadata)

        return {
            "$schema": CANONICAL_SCHEMA_URI,
            "id": fnd_id,
            "agent": self.default_agent,
            "origin": "deterministic_linter",
            "rule_id": rule_id,
            "category": category,
            "resource": resource,
            "fact": fact.strip(),
            "evidence": evidence,
            "recommendation": recommendation.strip(),
            "severity": severity,
            "confidence": None,
            "corroboration_status": "tool_verified",
            "metadata": full_meta,
        }

    def _infer_attribute_keyword(self, fact: str, rule_id: str) -> str | None:
        """Infers targeted attribute keyword from fact or rule for source line resolution."""
        fact_lower = fact.lower()
        if "force_destroy" in fact_lower:
            return "force_destroy"
        if "encryption" in fact_lower or "server_side_encryption" in fact_lower:
            return "server_side_encryption"
        if "multi_az" in fact_lower or "multi-az" in fact_lower:
            return "multi_az"
        if "privileged" in fact_lower:
            return "privileged"
        if "memory limit" in fact_lower or "memory" in fact_lower:
            return "memory"
        if "readinessprobe" in fact_lower or "readiness" in fact_lower:
            return "readinessProbe"
        return None

    def _extract_diff_file_lines(self, diff_text: str, target_file: str) -> list[tuple[int, str]]:
        """Extracts (file_line_num, line_content) pairs from diff hunks for target_file."""
        results: list[tuple[int, str]] = []
        norm_target = target_file.lstrip("/").replace("\\", "/")
        in_target_file = False
        new_line_num = 0

        for line in diff_text.splitlines():
            if line.startswith("diff --git "):
                parts = line.split(" ")
                if len(parts) >= 4:
                    b_path = parts[3]
                    b_norm = (b_path[2:] if b_path.startswith("b/") else b_path).lstrip("/").replace("\\", "/")
                    in_target_file = (b_norm == norm_target or b_norm.endswith(norm_target) or norm_target.endswith(b_norm))
                continue

            if not in_target_file:
                continue

            if line.startswith("--- ") or line.startswith("+++ "):
                continue

            hunk_match = HUNK_HEADER_PATTERN.match(line)
            if hunk_match:
                new_line_num = int(hunk_match.group(1))
                continue

            if line.startswith("+"):
                results.append((new_line_num, line[1:]))
                new_line_num += 1
            elif line.startswith(" "):
                results.append((new_line_num, line[1:]))
                new_line_num += 1
            elif line.startswith("-"):
                pass

        return results

    def _locate_source_span(
        self,
        target_file: str,
        res_address: str,
        attr_keyword: str | None = None,
        diff_text: str | None = None,
    ) -> tuple[int, int, bool]:
        """Locates source line span (start, end, is_resolved) in file or active diff."""
        indexed_lines: list[tuple[int, str]] = []
        path = self.repo_root / target_file
        if path.is_file():
            try:
                raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                indexed_lines = list(enumerate(raw_lines, start=1))
            except Exception:
                indexed_lines = []

        if not indexed_lines and diff_text:
            indexed_lines = self._extract_diff_file_lines(diff_text, target_file)

        if not indexed_lines:
            return 1, 1, False

        tokens = res_address.split(".")
        res_name = tokens[-1] if tokens else res_address
        res_type = tokens[0] if len(tokens) > 1 else ""

        block_start_idx = -1
        block_end_idx = -1

        for i, (line_no, line_text) in enumerate(indexed_lines):
            if res_name in line_text or (res_type and res_type in line_text):
                block_start_idx = i
                break

        if block_start_idx == -1:
            if attr_keyword:
                for line_no, line_text in indexed_lines:
                    if attr_keyword in line_text:
                        return line_no, line_no, True
            return 1, 1, False

        # Scan for closing brace or indentation end
        brace_count = 0
        found_open_brace = False
        for i in range(block_start_idx, len(indexed_lines)):
            _, line_text = indexed_lines[i]
            if "{" in line_text:
                found_open_brace = True
                brace_count += line_text.count("{") - line_text.count("}")
                if brace_count <= 0:
                    block_end_idx = i
                    break
            elif found_open_brace:
                brace_count += line_text.count("{") - line_text.count("}")
                if brace_count <= 0:
                    block_end_idx = i
                    break

        if block_end_idx == -1:
            _, start_text = indexed_lines[block_start_idx]
            base_indent = len(start_text) - len(start_text.lstrip())
            block_end_idx = block_start_idx
            for i in range(block_start_idx + 1, len(indexed_lines)):
                _, l_text = indexed_lines[i]
                if not l_text.strip():
                    continue
                ind = len(l_text) - len(l_text.lstrip())
                if ind > base_indent:
                    block_end_idx = i
                else:
                    break

        # If attr_keyword provided, search for exact attribute line inside block
        if attr_keyword:
            for i in range(block_start_idx, min(block_end_idx + 1, len(indexed_lines))):
                l_no, l_text = indexed_lines[i]
                if attr_keyword in l_text:
                    return l_no, l_no, True

        start_no = indexed_lines[block_start_idx][0]
        end_no = indexed_lines[block_end_idx][0]
        return start_no, max(start_no, end_no), True

    def _load_json(self, payload: Any) -> dict[str, Any]:
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, Path) or (isinstance(payload, str) and not payload.strip().startswith("{")):
            p = Path(payload)
            if not p.is_file():
                raise FileNotFoundError(f"JSON input file not found: '{p}'")
            return json.loads(p.read_text(encoding="utf-8"))
        if isinstance(payload, str):
            return json.loads(payload)
        raise TypeError(f"Unsupported payload type: {type(payload).__name__}")

    def _load_manifest_docs(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, list):
            return [d for d in payload if isinstance(d, dict)]
        if isinstance(payload, Path):
            if not payload.is_file():
                raise FileNotFoundError(f"Manifest input file not found: '{payload}'")
            return parse_manifest_documents(payload.read_text(encoding="utf-8", errors="replace"))
        if isinstance(payload, str):
            if "\n" not in payload and len(payload) < 1024:
                p = Path(payload)
                if p.is_file():
                    return parse_manifest_documents(p.read_text(encoding="utf-8", errors="replace"))
            return parse_manifest_documents(payload)
        raise TypeError(f"Unsupported payload type: {type(payload).__name__}")


def evaluate_manifest(
    manifest: dict[str, Any] | list[dict[str, Any]] | str | Path,
    target_file: str = "k8s/deployment.yaml",
    diff_text: str | None = None,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Functional helper evaluating a Kubernetes manifest against institutional policies."""
    evaluator = OpaEvaluator(repo_root=repo_root)
    return evaluator.evaluate_kubernetes_manifest(manifest, target_file=target_file, diff_text=diff_text)


def evaluate_terraform_plan(
    plan: dict[str, Any] | str | Path,
    target_file: str = "infra/main.tf",
    diff_text: str | None = None,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    """Functional helper evaluating a Terraform plan against institutional policies."""
    evaluator = OpaEvaluator(repo_root=repo_root)
    return evaluator.evaluate_terraform_plan(plan, target_file=target_file, diff_text=diff_text)
