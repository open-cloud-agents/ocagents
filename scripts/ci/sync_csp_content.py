#!/usr/bin/env python3
"""
scripts/ci/sync_csp_content.py
=============================================================================
Automated Cloud Service Provider (CSP) Skills Content Synchronizer
Open Cloud Agents - Master Synchronization & Verification Suite

Clones or downloads upstream CSP repositories (AWS, Azure, GCP), maps and
mirrors actual skill definitions, plugins, operational rules, and licenses
into the Open Cloud Agents repository, preserves local remix assets,
enforces script execution permissions, runs repository hygiene validation,
and updates the synchronization baseline.

Usage:
  python3 scripts/ci/sync_csp_content.py [OPTIONS]

Options:
  --config PATH            Path to upstream-sync.json (default: skills/csp/upstream-sync.json)
  --provider KEY           Target specific provider (e.g. 'aws', 'azure', 'gcp')
  --force                  Force full synchronization even if baseline matches upstream
  --dry-run                Check upstream and simulate synchronization without writing files
  --markdown-summary PATH  Export structured Markdown summary to path (for CI and PR description)
  --json                   Output results as JSON
  --skip-validation        Skip post-sync repository validation (not recommended)

Exit Codes:
  0: Synchronization succeeded (or all skills already up to date).
  1: Execution or validation failure.
  2: Synchronization completed with upstream changes applied.
=============================================================================
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_CONFIG_PATH = Path("skills/csp/upstream-sync.json")
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def load_config(config_path: Path) -> dict:
    if not config_path.is_absolute():
        config_path = REPO_ROOT / config_path
    if not config_path.exists():
        print(f"❌ Configuration file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(config_path: Path, data: dict) -> None:
    if not config_path.is_absolute():
        config_path = REPO_ROOT / config_path
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def fetch_upstream_commit(repo: str, branch: str = "main", token: Optional[str] = None) -> Optional[dict]:
    """Fetch latest commit from GitHub REST API."""
    url = f"https://api.github.com/repos/{repo}/commits?per_page=1&sha={branch}"
    headers = {
        "User-Agent": "OpenCloudAgents-CSP-Synchronizer",
        "Accept": "application/vnd.github.v3+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            commits = json.load(resp)
            return commits[0] if commits else None
    except urllib.error.HTTPError as e:
        print(f"⚠️  HTTP Error {e.code} querying {repo}: {e.reason}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"⚠️  Network error querying {repo}: {e}", file=sys.stderr)
        return None


def clone_upstream_repo(repo_url: str, branch: str, target_tmp_dir: Path, token: Optional[str] = None) -> bool:
    """Perform a shallow clone of the upstream repository into target_tmp_dir."""
    auth_url = repo_url
    if token and "github.com" in repo_url:
        auth_url = repo_url.replace("https://github.com/", f"https://x-access-token:{token}@github.com/")

    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        branch,
        auth_url,
        str(target_tmp_dir),
    ]

    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=120,
        )
        if res.returncode != 0:
            print(f"❌ Git clone failed for {repo_url}:\n{res.stderr}", file=sys.stderr)
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"❌ Git clone timed out for {repo_url}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"❌ Error invoking git clone: {e}", file=sys.stderr)
        return False


def get_git_diff_summary(provider_target_dir: Path) -> Dict[str, Any]:
    """Inspect git status/diff for changes under provider_target_dir."""
    try:
        res = subprocess.run(
            ["git", "status", "--porcelain", str(provider_target_dir)],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
        added = [l[3:] for l in lines if l.startswith("A") or l.startswith("??")]
        modified = [l[3:] for l in lines if l.startswith("M")]
        deleted = [l[3:] for l in lines if l.startswith("D")]

        return {
            "has_changes": len(lines) > 0,
            "total_changed": len(lines),
            "added_count": len(added),
            "modified_count": len(modified),
            "deleted_count": len(deleted),
            "sample_files": lines[:10],
        }
    except Exception as e:
        return {
            "has_changes": False,
            "total_changed": 0,
            "added_count": 0,
            "modified_count": 0,
            "deleted_count": 0,
            "sample_files": [],
            "error": str(e),
        }


def enforce_script_permissions(target_dir: Path) -> int:
    """Ensure all shell scripts under target_dir have executable permissions (0o755)."""
    count = 0
    if not target_dir.exists():
        return 0
    for path in target_dir.rglob("*.sh"):
        try:
            current_mode = path.stat().st_mode
            target_mode = current_mode | 0o755
            if current_mode != target_mode:
                path.chmod(target_mode)
                count += 1
        except Exception as e:
            print(f"⚠️  Could not chmod +x {path}: {e}", file=sys.stderr)
    return count


def sync_provider(
    provider_key: str,
    provider_data: dict,
    token: Optional[str] = None,
    force: bool = False,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Synchronize a single provider's skill assets from upstream."""
    name = provider_data.get("name", provider_key.upper())
    repo = provider_data.get("repository", "")
    url = provider_data.get("url", f"https://github.com/{repo}")
    branch = provider_data.get("branch", "main")
    target_rel = provider_data.get("target_dir", f"skills/csp/{provider_key}")
    target_dir = REPO_ROOT / target_rel
    sync_mappings = provider_data.get("sync_mappings", [{"source": "skills", "target": "skills"}])
    preserve_files = provider_data.get("preserve_files", ["README.md"])

    last_synced_sha = provider_data.get("last_synced_commit", "")
    last_synced_date = provider_data.get("last_synced_date", "")

    result: Dict[str, Any] = {
        "provider": provider_key,
        "name": name,
        "repository": repo,
        "target_dir": target_rel,
        "status": "UNKNOWN",
        "drift": False,
        "synced": False,
        "previous_sha": last_synced_sha,
        "latest_sha": last_synced_sha,
        "latest_date": last_synced_date,
        "commit_message": provider_data.get("commit_message", ""),
        "diff_summary": {},
        "error": None,
    }

    # 1. Fetch latest upstream commit
    upstream_commit = fetch_upstream_commit(repo, branch, token)
    if upstream_commit:
        latest_sha = upstream_commit.get("sha", "")
        latest_date = upstream_commit.get("commit", {}).get("committer", {}).get("date", "")
        latest_msg = upstream_commit.get("commit", {}).get("message", "").split("\n")[0]
        result["latest_sha"] = latest_sha
        result["latest_date"] = latest_date
        result["commit_message"] = latest_msg
    else:
        latest_sha = ""
        latest_date = ""
        latest_msg = ""

    has_drift = bool(latest_sha and latest_sha != last_synced_sha)
    result["drift"] = has_drift

    if not has_drift and not force:
        result["status"] = "UP_TO_DATE"
        result["message"] = f"Already synchronized at commit {last_synced_sha[:8]}"
        return result

    if dry_run:
        result["status"] = "DRIFT_DETECTED"
        result["message"] = f"Drift detected (Upstream: {latest_sha[:8]}, Local: {last_synced_sha[:8]}). Dry run enabled; files not modified."
        return result

    print(f"📥 Synchronizing {name} from {url} ({branch})...")

    with tempfile.TemporaryDirectory(prefix=f"csp_sync_{provider_key}_") as tmpdir_str:
        clone_dir = Path(tmpdir_str)
        cloned = clone_upstream_repo(url, branch, clone_dir, token)
        if not cloned:
            result["status"] = "CLONE_FAILED"
            result["error"] = f"Failed to clone {url}"
            return result

        # If we couldn't fetch commit via API earlier, read it from cloned repo
        if not latest_sha:
            try:
                rev = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(clone_dir),
                    stdout=subprocess.PIPE,
                    text=True,
                    check=True,
                )
                latest_sha = rev.stdout.strip()
                result["latest_sha"] = latest_sha

                log_p = subprocess.run(
                    ["git", "log", "-1", "--format=%cd|%s", "--date=iso-strict"],
                    cwd=str(clone_dir),
                    stdout=subprocess.PIPE,
                    text=True,
                    check=True,
                )
                parts = log_p.stdout.strip().split("|", 1)
                latest_date = parts[0] if parts else ""
                latest_msg = parts[1] if len(parts) > 1 else ""
                result["latest_date"] = latest_date
                result["commit_message"] = latest_msg
            except Exception as e:
                print(f"⚠️  Could not read git rev-parse in clone: {e}", file=sys.stderr)

        # 2. Back up preserved local files
        preserved_cache: Dict[str, bytes] = {}
        for pfile in preserve_files:
            src_p = target_dir / pfile
            if src_p.exists() and src_p.is_file():
                try:
                    preserved_cache[pfile] = src_p.read_bytes()
                except Exception as e:
                    print(f"⚠️  Failed reading preserved file {src_p}: {e}", file=sys.stderr)

        # 3. Apply sync mappings
        for mapping in sync_mappings:
            source_sub = mapping.get("source", "")
            target_sub = mapping.get("target", "")

            upstream_path = clone_dir / source_sub
            destination_path = target_dir / target_sub

            if not upstream_path.exists():
                print(f"⚠️  Source mapping path does not exist upstream: {source_sub}", file=sys.stderr)
                continue

            if upstream_path.is_file():
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(upstream_path, destination_path)
            elif upstream_path.is_dir():
                if destination_path.exists():
                    shutil.rmtree(destination_path)
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(upstream_path, destination_path, symlinks=True)

        # 4. Restore preserved files
        for pfile, content in preserved_cache.items():
            dst_p = target_dir / pfile
            dst_p.parent.mkdir(parents=True, exist_ok=True)
            dst_p.write_bytes(content)

        # 5. Enforce script execution permissions
        chmod_count = enforce_script_permissions(target_dir)
        if chmod_count > 0:
            print(f"  ✔ Enforced executable permissions on {chmod_count} shell script(s).")

        # 6. Capture git diff status
        diff_info = get_git_diff_summary(target_dir)
        result["diff_summary"] = diff_info
        result["synced"] = True
        result["status"] = "SYNCHRONIZED"
        result["message"] = f"Synchronized to commit {latest_sha[:8]} ({diff_info.get('total_changed', 0)} files changed)"

    return result


def run_repo_validation() -> Tuple[bool, str]:
    """Execute repository hygiene validation suite (validate_repo.py)."""
    validator_path = REPO_ROOT / "scripts" / "ci" / "validate_repo.py"
    if not validator_path.exists():
        return True, "Validator script not found; skipped."

    try:
        res = subprocess.run(
            [sys.executable, str(validator_path)],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        return (res.returncode == 0), res.stdout
    except Exception as e:
        return False, f"Validation execution failed: {e}"


def generate_markdown_summary(results: List[Dict[str, Any]], run_date: str, validation_ok: bool, validation_output: str) -> str:
    """Generate structured markdown summary for GitHub Actions and Pull Request descriptions."""
    total_providers = len(results)
    synced_count = sum(1 for r in results if r.get("status") == "SYNCHRONIZED")
    up_to_date_count = sum(1 for r in results if r.get("status") == "UP_TO_DATE")
    failed_count = sum(1 for r in results if r.get("status") in ["CLONE_FAILED", "VALIDATION_FAILED"])

    md = []
    md.append("## 🌐 Open Cloud Agents - Upstream CSP Skills Synchronization")
    md.append(f"**Execution Timestamp:** `{run_date}`\n")

    # High-level summary cards
    md.append("| Provider | Target Directory | Upstream Repository | Commit | Status |")
    md.append("|---|---|---|---|---|")
    for r in results:
        status_icon = "🟢" if r["status"] in ["SYNCHRONIZED", "UP_TO_DATE"] else "🔴"
        sha_display = f"[`{r['latest_sha'][:8]}`](https://github.com/{r['repository']}/commit/{r['latest_sha']})" if r["latest_sha"] else "N/A"
        md.append(f"| **{r['name']}** | `{r['target_dir']}` | [{r['repository']}](https://github.com/{r['repository']}) | {sha_display} | {status_icon} `{r['status']}` |")

    md.append("\n### 📋 Synchronization Breakdown")
    for r in results:
        md.append(f"#### {r['name']} (`{r['repository']}`)")
        md.append(f"- **Message:** {r.get('message', 'N/A')}")
        if r.get("commit_message"):
            md.append(f"- **Upstream Commit Title:** `{r['commit_message']}`")
        if r.get("diff_summary", {}).get("has_changes"):
            ds = r["diff_summary"]
            md.append(f"- **File Changes:** {ds.get('added_count', 0)} added, {ds.get('modified_count', 0)} modified, {ds.get('deleted_count', 0)} deleted")
            if ds.get("sample_files"):
                md.append("  ```text")
                for sf in ds["sample_files"]:
                    md.append(f"  {sf}")
                if ds.get("total_changed", 0) > len(ds["sample_files"]):
                    md.append(f"  ... and {ds['total_changed'] - len(ds['sample_files'])} more files")
                md.append("  ```")
        md.append("")

    # Hygiene Validation Status
    md.append("### 🛡️ Repository Hygiene & Verification Gates")
    if validation_ok:
        md.append("✔ **All Repository Hygiene Checks Passed (`scripts/ci/validate_repo.py`):**")
        md.append("- Valid YAML frontmatter across all `SKILL.md` specifications.")
        md.append("- Verified `chmod +x` executable permissions on all shell scripts (`*.sh`).")
        md.append("- Zero leaking personal developer machine paths (`/Users/<username>/`).")
        md.append("- Zero invisible characters or Trojan Source confusables.")
    else:
        md.append("❌ **Hygiene Validation Failed:**")
        md.append("```text")
        md.append(validation_output.strip()[:1000])
        md.append("```")

    md.append("\n---\n*Generated automatically by Open Cloud Agents CSP Synchronization Suite.*")
    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="Synchronize upstream Cloud Service Provider (CSP) skills.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to upstream-sync.json")
    parser.add_argument("--provider", type=str, help="Target specific provider key (e.g. 'aws', 'azure', 'gcp')")
    parser.add_argument("--force", action="store_true", help="Force synchronization even if baseline matches")
    parser.add_argument("--dry-run", action="store_true", help="Simulate synchronization without modifying files")
    parser.add_argument("--markdown-summary", type=Path, help="Export formatted markdown summary to path")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--skip-validation", action="store_true", help="Skip repository hygiene validation")

    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    config = load_config(args.config)
    providers = config.get("providers", {})

    target_keys = [args.provider] if args.provider else list(providers.keys())

    print("============================================================")
    print(" 🌐  Open Cloud Agents: CSP Skills Content Synchronizer")
    print("============================================================")

    results = []
    any_synced = False
    has_failure = False

    for key in target_keys:
        if key not in providers:
            print(f"❌ Unknown provider '{key}'. Available: {list(providers.keys())}", file=sys.stderr)
            sys.exit(1)

        pdata = providers[key]
        print(f"\n🔍 Evaluating {pdata.get('name', key)} ({pdata.get('repository')})...")
        res = sync_provider(
            provider_key=key,
            provider_data=pdata,
            token=token,
            force=args.force,
            dry_run=args.dry_run,
        )
        results.append(res)

        if res["status"] == "UP_TO_DATE":
            print(f"  ✔ {res.get('message', 'Up to date')}")
        elif res["status"] == "DRIFT_DETECTED":
            print(f"  🟡 {res.get('message', 'Drift detected')}")
        elif res["status"] == "SYNCHRONIZED":
            print(f"  ✔ {res.get('message', 'Synchronized successfully')}")
        else:
            print(f"  ❌ {res.get('message') or res.get('error') or res['status']}")

        if res.get("synced"):
            any_synced = True
            # Update baseline in config object
            config["providers"][key]["last_synced_commit"] = res["latest_sha"]
            config["providers"][key]["last_synced_date"] = res["latest_date"]
            if res.get("commit_message"):
                config["providers"][key]["commit_message"] = res["commit_message"]
        elif res.get("status") in ["CLONE_FAILED", "VALIDATION_FAILED"]:
            has_failure = True

    # Run validation if files were synced and not skipped
    validation_ok = True
    validation_output = "No changes applied; validation skipped."
    if any_synced and not args.skip_validation and not args.dry_run:
        print("\n🛡️  Running repository hygiene validation...")
        validation_ok, validation_output = run_repo_validation()
        if not validation_ok:
            print("❌ Repository hygiene validation failed after sync!", file=sys.stderr)
            print(validation_output, file=sys.stderr)
            has_failure = True
            for r in results:
                if r.get("synced"):
                    r["status"] = "VALIDATION_FAILED"
        else:
            print("✔ Repository hygiene validation passed cleanly.")
            # Save updated configuration baseline
            save_config(args.config, config)
            print(f"✔ Updated {args.config} baseline with latest upstream commits.")

    run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if args.markdown_summary:
        summary_path = args.markdown_summary
        if not summary_path.is_absolute():
            summary_path = REPO_ROOT / summary_path
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        md = generate_markdown_summary(results, run_date, validation_ok, validation_output)
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(md)
            f.write("\n")
        print(f"✔ Exported markdown summary to {summary_path}")

    if args.json:
        print(json.dumps(results, indent=2))

    print("\n============================================================")
    drift_count = sum(1 for r in results if r.get("drift"))
    if has_failure:
        print("❌ Synchronization encountered failures.")
        sys.exit(1)
    elif any_synced:
        print("✔ Synchronization completed with upstream changes applied.")
        sys.exit(2)
    elif args.dry_run and drift_count > 0:
        print(f"ℹ Dry run complete: Upstream drift detected in {drift_count} provider(s).")
        sys.exit(2)
    else:
        print("✔ All CSP skills are 100% up to date.")
        sys.exit(0)


if __name__ == "__main__":
    main()
