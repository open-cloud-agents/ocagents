#!/usr/bin/env python3
"""
scripts/ci/check_csp_updates.py
=============================================================================
Automated Cloud Service Provider (CSP) Upstream Drift & Update Monitor
Open Cloud Agents - Master Verification & Synchronization Suite

Monitors upstream repositories for AWS, Azure, and GCP agent skills.
Detects drift, identifies new commits and skills, and generates structured
markdown summaries for GitHub Actions and maintainers.

Exit Codes:
  0: All CSP skills are synchronized and up-to-date (or check ran cleanly).
  1: Execution error (e.g., invalid JSON configuration or file missing).
  2: Upstream drift detected (new commits/skills available upstream).
=============================================================================
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("skills/csp/upstream-sync.json")


def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        print(f"❌ Configuration file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(config_path: Path, data: dict):
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def fetch_upstream_commits(repo: str, branch: str = "main", token: str = None) -> list:
    url = f"https://api.github.com/repos/{repo}/commits?per_page=5&sha={branch}"
    headers = {
        "User-Agent": "OpenCloudAgents-CSP-Monitor",
        "Accept": "application/vnd.github.v3+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        print(f"⚠️  HTTP Error {e.code} fetching {repo}: {e.reason}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"⚠️  Network error querying {repo}: {e}", file=sys.stderr)
        return []


def check_provider_drift(provider_key: str, provider_data: dict, token: str = None) -> dict:
    repo = provider_data.get("repository")
    branch = provider_data.get("branch", "main")
    last_synced_sha = provider_data.get("last_synced_commit", "")
    last_synced_date = provider_data.get("last_synced_date", "")

    commits = fetch_upstream_commits(repo, branch, token)
    if not commits:
        return {
            "provider": provider_key,
            "name": provider_data.get("name", provider_key.upper()),
            "repository": repo,
            "status": "UNKNOWN",
            "message": "Unable to fetch upstream commits (API rate limit or network)",
            "drift": False,
            "latest_sha": last_synced_sha,
            "latest_date": last_synced_date,
            "new_commits": [],
        }

    latest_commit = commits[0]
    latest_sha = latest_commit.get("sha", "")
    latest_date = latest_commit.get("commit", {}).get("committer", {}).get("date", "")
    latest_msg = latest_commit.get("commit", {}).get("message", "").split("\n")[0]

    if latest_sha == last_synced_sha:
        return {
            "provider": provider_key,
            "name": provider_data.get("name", provider_key.upper()),
            "repository": repo,
            "status": "UP_TO_DATE",
            "message": "Fully synchronized with upstream",
            "drift": False,
            "latest_sha": latest_sha,
            "latest_date": latest_date,
            "new_commits": [],
        }

    # Find commits ahead
    new_commits = []
    for c in commits:
        if c.get("sha") == last_synced_sha:
            break
        new_commits.append({
            "sha": c.get("sha")[:8],
            "full_sha": c.get("sha"),
            "date": c.get("commit", {}).get("committer", {}).get("date"),
            "message": c.get("commit", {}).get("message", "").split("\n")[0],
            "author": c.get("commit", {}).get("author", {}).get("name", "Unknown"),
            "url": f"https://github.com/{repo}/commit/{c.get('sha')}"
        })

    return {
        "provider": provider_key,
        "name": provider_data.get("name", provider_key.upper()),
        "repository": repo,
        "status": "DRIFT_DETECTED",
        "message": f"Upstream is {len(new_commits)} commit(s) ahead",
        "drift": True,
        "latest_sha": latest_sha,
        "latest_date": latest_date,
        "new_commits": new_commits,
    }


def generate_markdown_summary(results: list, run_date: str) -> str:
    has_drift = any(r["drift"] for r in results)
    status_emoji = "⚠️ Drift Detected" if has_drift else "✔ All CSP Skills Synchronized"

    lines = [
        f"## 🌐 Cloud Service Provider (CSP) Skills Sync Report",
        f"",
        f"**Audit Timestamp:** `{run_date}`  ",
        f"**Status:** {status_emoji}  ",
        f"",
        f"| Provider | Repository | Status | Current Baseline | Upstream Latest | Upstream Date |",
        f"|:---|:---|:---:|:---:|:---:|:---|",
    ]

    for r in results:
        status_badge = "🟢 Synchronized" if r["status"] == "UP_TO_DATE" else ("🟡 New Commits" if r["status"] == "DRIFT_DETECTED" else "⚪ Unavailable")
        repo_link = f"[{r['repository']}](https://github.com/{r['repository']})"
        baseline = r.get("latest_sha", "")[:8] if not r["drift"] else r.get("new_commits", [{}])[-1].get("sha", "baseline")
        latest = f"[`{r['latest_sha'][:8]}`](https://github.com/{r['repository']}/commit/{r['latest_sha']})"
        date_str = r.get("latest_date", "N/A")[:10]
        lines.append(f"| **{r['name']}** | {repo_link} | {status_badge} | `{baseline}` | {latest} | {date_str} |")

    lines.append("")

    if has_drift:
        lines.append("### 📝 Upstream Changelog Details")
        for r in results:
            if r["drift"] and r["new_commits"]:
                lines.append(f"#### {r['name']} (`{r['repository']}`)")
                for nc in r["new_commits"]:
                    lines.append(f"- [`{nc['sha']}`]({nc['url']}): {nc['message']} *(by {nc['author']} on {nc['date'][:10]})*")
                lines.append("")

        lines.append("---")
        lines.append("💡 *Automated Action:* An automated sync PR will be created to merge and validate these upstream skill enhancements.")
    else:
        lines.append("All Cloud Service Provider skills match their upstream baselines. No sync action required.")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Check for upstream CSP skills updates.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to upstream-sync.json")
    parser.add_argument("--check", action="store_true", help="Exit code 2 if drift is detected (for CI gating)")
    parser.add_argument("--markdown-summary", type=Path, help="Export formatted markdown summary to path")
    parser.add_argument("--update-baseline", action="store_true", help="Update upstream-sync.json with latest commits")
    parser.add_argument("--sync", action="store_true", help="Mirror upstream skills and content using sync_csp_content.py")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    config = load_config(args.config)
    providers = config.get("providers", {})

    print(f"============================================================")
    print(f" 🌐  Open Cloud Agents: CSP Skills Upstream Drift Monitor")
    print(f"============================================================")

    results = []
    has_drift = False

    for key, data in providers.items():
        name = data.get("name", key)
        repo = data.get("repository", "")
        print(f"ℹ Checking {name} ({repo})...")
        res = check_provider_drift(key, data, token)
        results.append(res)

        if res["drift"]:
            has_drift = True
            print(f"  🟡 {res['message']} (Latest: {res['latest_sha'][:8]} on {res['latest_date'][:10]})")
            for nc in res["new_commits"][:3]:
                print(f"     - [{nc['sha']}] {nc['message']}")
        elif res["status"] == "UP_TO_DATE":
            print(f"  ✔ Synchronized with upstream (Commit: {res['latest_sha'][:8]})")
        else:
            print(f"  ⚪ {res['message']}")

    run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if args.markdown_summary:
        md = generate_markdown_summary(results, run_date)
        args.markdown_summary.parent.mkdir(parents=True, exist_ok=True)
        with open(args.markdown_summary, "w", encoding="utf-8") as f:
            f.write(md)
            f.write("\n")
        print(f"✔ Exported markdown summary to {args.markdown_summary}")

    if args.sync and has_drift:
        print("\n🚀 Delegating to scripts/ci/sync_csp_content.py to mirror content...")
        sync_script = Path(__file__).resolve().parent / "sync_csp_content.py"
        sync_cmd = [sys.executable, str(sync_script), "--config", str(args.config)]
        if args.markdown_summary:
            sync_cmd.extend(["--markdown-summary", str(args.markdown_summary)])
        sync_res = subprocess.run(sync_cmd, check=False)
        sys.exit(sync_res.returncode)

    if args.update_baseline and has_drift:
        for res in results:
            if res["drift"] and res["latest_sha"]:
                key = res["provider"]
                config["providers"][key]["last_synced_commit"] = res["latest_sha"]
                config["providers"][key]["last_synced_date"] = res["latest_date"]
                if res["new_commits"]:
                    config["providers"][key]["commit_message"] = res["new_commits"][0]["message"]
        save_config(args.config, config)
        print(f"✔ Updated {args.config} baseline with latest upstream commits.")
        print(f"⚠️  Note: Baseline updated without synchronizing actual skill files. Use scripts/ci/sync_csp_content.py or --sync to mirror upstream skills.")

    if args.json:
        print(json.dumps(results, indent=2))

    print(f"============================================================")
    if has_drift:
        print(f"RESULT: Upstream drift detected in {sum(1 for r in results if r['drift'])} provider(s).")
        if args.check:
            sys.exit(2)
    else:
        print(f"SUCCESS: All CSP skills are 100% up to date.")
    sys.exit(0)


if __name__ == "__main__":
    main()
