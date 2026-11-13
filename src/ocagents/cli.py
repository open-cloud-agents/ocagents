#!/usr/bin/env python3
"""
Open Cloud Agents: Universal CLI (ocagents).

Production CLI for syncing, listing, validating, and running Open Cloud Agents
specialist personas and skills across GitHub Copilot, Cursor, Claude Code, and Gemini.

Packaging & Performance Invariants:
- Zero Top-Level 3P Dependencies: Top-level imports strictly restricted to Python stdlib.
- Sub-10ms Cold-Start: Defer all heavy imports (PyYAML, SDKs) into subcommand functions.
- Hermetic Distribution: Supports Homebrew Cellar virtualenv isolation and PyInstaller standalone binaries.

Usage:
    ocagents list
    ocagents -a ls
    ocagents sync --all --format github --target /path/to/repo --sync-skills
    ocagents -A -format github --target /path/to/repo
    ocagents validate
    ocagents run --task "Architect multi-region payment DR"
    ocagents info
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

# Ensure src directory is in sys.path when running from repository root
_src_dir = str(Path(__file__).resolve().parent.parent)
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

__version__ = "1.6.0"

CANONICAL_REPO_URL = "https://github.com/open-cloud-agents/ocagents.git"
AVAILABLE_FORMATS = ["github", "claude", "cursor", "gemini", "raw"]
UPDATE_CHECK_INTERVAL_SECONDS = 86400  # 24 hours
GITHUB_LATEST_RELEASE_API = "https://api.github.com/repos/open-cloud-agents/ocagents/releases/latest"

OCA_ASCII_BANNER = r"""
 ██████╗  ██████╗  █████╗ 
██╔═══██╗██╔════╝ ██╔══██╗
██║   ██║██║      ███████║
██║   ██║██║      ██╔══██║
╚██████╔╝╚██████╗ ██║  ██║
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝"""


def get_cli_header() -> str:
    """Returns the stylized OCA ASCII banner and title string."""
    use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    c_cyan = "\033[36m" if use_color else ""
    c_bold = "\033[1m" if use_color else ""
    c_reset = "\033[0m" if use_color else ""
    banner = OCA_ASCII_BANNER.strip("\n")
    return f"{c_cyan}{banner}{c_reset}\n{c_bold}Open Cloud Agents (v{__version__}){c_reset}"


def parse_semver(v: str) -> tuple[int, ...]:
    """Parses a semantic version string (e.g. 'v1.3.3', '1.4.0-rc1') into an integer tuple."""
    clean = re.sub(r"^[^\d]*", "", (v or "").strip()).split("-")[0].split("+")[0]
    parts = [int(x) for x in clean.split(".") if x.isdigit()]
    return tuple(parts)


def get_update_cache_file() -> Path:
    """Returns the persistent cache path for version update checks."""
    cache_base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache_base / "ocagents" / "update_check.json"


def detect_install_method() -> tuple[str, str]:
    """Detects how ocagents was installed and returns (method_name, upgrade_command)."""
    exe = sys.executable or ""
    binary_path = sys.argv[0] or ""

    # 1. Homebrew
    if (
        "Cellar" in exe
        or "homebrew" in exe.lower()
        or "/opt/homebrew" in binary_path
        or "/usr/local/Cellar" in binary_path
    ):
        return ("homebrew", "brew update && brew upgrade ocagents")

    # 2. Pipx
    if "pipx" in exe.lower() or "pipx" in binary_path.lower():
        return ("pipx", "pipx upgrade ocagents")

    # 3. Windows WinGet
    if sys.platform == "win32":
        return ("winget", "winget upgrade OpenCloudAgents.ocagents")

    # 4. Alpine Linux
    if Path("/etc/alpine-release").exists():
        return ("apk", "apk update && apk upgrade ocagents")

    # 5. Generic curl / shell fallback
    return ("curl", "curl -fsSL https://open-cloud-agents.github.io/ocagents/install.sh | bash")


def fetch_latest_release(timeout: float = 1.2) -> dict | None:
    """Queries the GitHub API for the latest published release (fails silently)."""
    try:
        req = urllib.request.Request(
            GITHUB_LATEST_RELEASE_API,
            headers={"User-Agent": f"ocagents-cli/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                payload = json.loads(resp.read().decode("utf-8"))
                tag = (payload.get("tag_name") or "").lstrip("v")
                html_url = payload.get("html_url") or "https://github.com/open-cloud-agents/ocagents/releases"
                if tag:
                    return {
                        "last_check_epoch": int(time.time()),
                        "latest_version": tag,
                        "html_url": html_url,
                    }
    except Exception:
        pass
    return None


def init_background_update_check():
    """Initializes a non-blocking background thread to refresh the release cache if expired."""
    if (
        not sys.stdout.isatty()
        or os.environ.get("OCAGENTS_NO_UPDATE_NOTIFIER", "").lower() in ("1", "true", "yes")
        or os.environ.get("CI")
        or os.environ.get("GITHUB_ACTIONS")
    ):
        return

    cache_file = get_update_cache_file()
    now = int(time.time())

    if cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            last_check = data.get("last_check_epoch", 0)
            if now - last_check < UPDATE_CHECK_INTERVAL_SECONDS:
                return  # Cache is still fresh (< 24h)
        except Exception:
            pass

    def _worker():
        res = fetch_latest_release(timeout=1.5)
        if res:
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps(res), encoding="utf-8")
            except Exception:
                pass

    threading.Thread(target=_worker, daemon=True).start()


def notify_update_if_available():
    """Checks the cached version and renders a clean notice box to stderr if a newer version is available."""
    if (
        not sys.stderr.isatty()
        or os.environ.get("OCAGENTS_NO_UPDATE_NOTIFIER", "").lower() in ("1", "true", "yes")
        or os.environ.get("CI")
        or os.environ.get("GITHUB_ACTIONS")
    ):
        return

    # Skip in machine-readable output modes or update subcommands
    for arg in sys.argv:
        if arg.startswith("--export-json") or arg in ("update", "upgrade"):
            return

    cache_file = get_update_cache_file()
    if not cache_file.exists():
        return

    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        latest_ver = data.get("latest_version", "")
        html_url = data.get("html_url", "https://github.com/open-cloud-agents/ocagents/releases")
        if not latest_ver:
            return

        current_tuple = parse_semver(__version__)
        latest_tuple = parse_semver(latest_ver)

        if latest_tuple > current_tuple:
            _, upgrade_cmd = detect_install_method()
            use_color = "NO_COLOR" not in os.environ
            c_cyan = "\033[36m" if use_color else ""
            c_yellow = "\033[33m" if use_color else ""
            c_bold = "\033[1m" if use_color else ""
            c_dim = "\033[2m" if use_color else ""
            c_reset = "\033[0m" if use_color else ""

            line1 = f"  Update available: v{__version__} → v{latest_ver}"
            line2 = f"  To upgrade: {upgrade_cmd}"
            line3 = f"  Changelog:  {html_url}"

            content_len = max(len(line1), len(line2), len(line3)) + 4
            top = f"╭{'─' * content_len}╮"
            bot = f"╰{'─' * content_len}╯"

            sys.stderr.write(f"\n{c_yellow}{top}{c_reset}\n")
            sys.stderr.write(
                f"{c_yellow}│{c_reset}  {c_bold}Update available:{c_reset} {c_dim}v{__version__}{c_reset} → {c_bold}{c_cyan}v{latest_ver}{c_reset}"
                + " " * (content_len - len(line1))
                + f"{c_yellow}│{c_reset}\n"
            )
            sys.stderr.write(
                f"{c_yellow}│{c_reset}  To upgrade: {c_cyan}{upgrade_cmd}{c_reset}"
                + " " * (content_len - len(line2))
                + f"{c_yellow}│{c_reset}\n"
            )
            sys.stderr.write(
                f"{c_yellow}│{c_reset}  Changelog:  {c_dim}{html_url}{c_reset}"
                + " " * (content_len - len(line3))
                + f"{c_yellow}│{c_reset}\n"
            )
            sys.stderr.write(f"{c_yellow}{bot}{c_reset}\n\n")
    except Exception:
        pass


def resolve_asset_root() -> Path:
    """Dynamically resolves the root directory containing agents/ and skills/."""
    # 1. Check explicit environment override
    env_root = os.environ.get("OCAGENTS_HOME")
    if env_root and Path(env_root).exists() and (Path(env_root) / "agents").exists():
        return Path(env_root).resolve()

    # 2. Check PyInstaller standalone bundle (_MEIPASS)
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass_root = Path(sys._MEIPASS)
        if (meipass_root / "agents" / "7-agent-master-suite").exists():
            return meipass_root

    # 3. Check if running inside the cloned git repository
    file_dir = Path(__file__).resolve().parent
    repo_candidate = file_dir.parent.parent
    if (repo_candidate / "agents" / "7-agent-master-suite").exists():
        return repo_candidate

    # 4. Check Homebrew Cellar virtualenv share paths & Unix system shares
    sys_prefix = Path(sys.prefix).resolve()
    for share_candidate in [
        sys_prefix.parent / "share" / "ocagents",
        sys_prefix.parent.parent / "share" / "ocagents",
        Path("/opt/homebrew/share/ocagents"),
        Path("/usr/local/share/ocagents"),
        Path("/usr/share/ocagents"),
    ]:
        if (share_candidate / "agents" / "7-agent-master-suite").exists():
            return share_candidate

    # 5. Check standard user installation directory (~/.open-cloud-agents)
    user_home_candidate = Path.home() / ".open-cloud-agents"
    if (user_home_candidate / "agents" / "7-agent-master-suite").exists():
        return user_home_candidate

    # Fallback to current working directory
    return Path.cwd().resolve()


def get_agents_dir(asset_root: Path) -> Path:
    return asset_root / "agents" / "7-agent-master-suite"


def get_skills_dir(asset_root: Path) -> Path:
    return asset_root / "skills"


def log_pass(msg: str):
    print(f"  \033[92m✔\033[0m {msg}")


def log_fail(msg: str):
    print(f"  \033[91m✖\033[0m {msg}")


def log_info(msg: str):
    print(f"\033[94mℹ\033[0m {msg}")


from ocagents.frontmatter import parse_agent_frontmatter, parse_frontmatter


def get_available_agents(agents_dir: Path) -> dict[str, Path]:
    """Retrieve map of agent slug to Path."""
    agents = {}
    if not agents_dir.exists():
        return agents
    for p in agents_dir.glob("*.md"):
        slug = p.stem
        agents[slug] = p
    return agents


DOMAIN_COLORS = {
    "security": "\033[32m",        # Green
    "devops": "\033[34m",          # Blue
    "finops": "\033[33m",          # Yellow
    "csp": "\033[35m",             # Magenta
    "programming": "\033[36m",     # Cyan
    "continual-learning": "\033[93m", # Amber / Bright Yellow
    "data-science": "\033[96m",    # Bright Cyan
}


def colorize_skill(skill: str, use_color: bool = True) -> str:
    """Color-code skill path by domain prefix."""
    if not use_color:
        return skill
    if "/" not in skill:
        return f"\033[36m{skill}\033[0m"
    domain, rest = skill.split("/", 1)
    color = DOMAIN_COLORS.get(domain, "\033[37m")
    return f"{color}{domain}\033[0m/{rest}"


def format_skill_list(skills: list[str], use_color: bool = True, indent: str = "        ") -> str:
    """Neatly wraps colorized skill items across lines without awkward wrapping."""
    if not skills:
        return f"{indent}\033[90mNone declared\033[0m" if use_color else f"{indent}None declared"

    colored = [colorize_skill(s, use_color) for s in skills]
    lines = []
    curr_line = []
    curr_len = 0
    max_len = 82 - len(indent)

    for s_colored, s_raw in zip(colored, skills):
        item_len = len(s_raw) + 2
        if curr_line and (curr_len + item_len > max_len):
            lines.append(indent + ", ".join(curr_line) + ",")
            curr_line = [s_colored]
            curr_len = item_len
        else:
            curr_line.append(s_colored)
            curr_len += item_len
    if curr_line:
        lines.append(indent + ", ".join(curr_line))
    return "\n".join(lines)


def cmd_list(asset_root: Path):
    """List all agents in the Master Suite and their linked skills."""
    agents_dir = get_agents_dir(asset_root)
    agents = get_available_agents(agents_dir)
    use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    c_bold_cyan = "\033[1;36m" if use_color else ""
    c_bold_white = "\033[1;37m" if use_color else ""
    c_dim = "\033[90m" if use_color else ""
    c_green = "\033[32m" if use_color else ""
    c_yellow = "\033[33m" if use_color else ""
    c_cyan = "\033[36m" if use_color else ""
    c_reset = "\033[0m" if use_color else ""
    c_bold = "\033[1m" if use_color else ""

    print(f"\n{get_cli_header()}")
    print(f"🏛️  {c_bold}7-Agent Master Suite Registry{c_reset}")
    print("=" * 70)
    if not agents:
        log_fail(f"No agents found in {agents_dir}. Run 'ocagents update' to initialize assets.")
        return 1

    for slug, p in sorted(agents.items()):
        meta, _ = parse_agent_frontmatter(p)
        name = meta.get("name", slug)
        skills = meta.get("skills", [])
        tools = meta.get("tools", [])
        tb = meta.get("token_budget")
        hc = meta.get("handoff_contract")
        print(f"{c_bold_cyan}• {slug}{c_reset}: {c_bold_white}{name}{c_reset}")
        print(f"    {c_dim}↳ Tools:{c_reset} {c_green}[{', '.join(tools)}]{c_reset}")
        if isinstance(tb, dict):
            ctx_t = tb.get("max_context_tokens", "N/A")
            out_t = tb.get("max_output_tokens", "N/A")
            tot_t = tb.get("max_session_total_tokens", "N/A")
            print(f"    {c_dim}↳ Token Budget:{c_reset} {c_yellow}context: {ctx_t} | output: {out_t} | session: {tot_t}{c_reset}")
        if isinstance(hc, dict):
            in_s = hc.get("input_schema") or "none"
            out_s = hc.get("output_schema") or "none"
            print(f"    {c_dim}↳ Handoff Contract:{c_reset} {c_cyan}in: {in_s} ➔ out: {out_s}{c_reset}")
        if skills:
            print(f"    {c_dim}↳ Linked Skills ({len(skills)}):{c_reset}")
            print(format_skill_list(skills, use_color=use_color))
        else:
            print(f"    {c_dim}↳ Linked Skills:{c_reset} {c_dim}None declared{c_reset}")
    print("=" * 70)
    print(f"{c_bold}Tip:{c_reset} Sync all agents:    {c_green}ocagents sync -A --format github --target .{c_reset}")
    print(f"     Sync a specialist:  {c_green}ocagents sync devsecops-reviewer --format github --target .{c_reset}\n")
    return 0


def transform_for_cursor(meta: dict, body: str) -> str:
    """Format markdown file as a Cursor Rule (.mdc)."""
    desc = meta.get("description", "Open Cloud Agents specialist assistant")
    frontmatter = f"""---
description: "{desc}"
globs: "*"
alwaysApply: false
---
"""
    return frontmatter + body


def sync_single_agent(
    agent_slug: str,
    agent_path: Path,
    target_root: Path,
    fmt: str,
    sync_skills: bool,
    use_symlink: bool,
    dry_run: bool,
    skills_dir: Path,
) -> bool:
    """Synchronize an agent and optionally its skills into the target workspace."""
    meta, body = parse_agent_frontmatter(agent_path)
    name = meta.get("name", agent_slug)
    log_info(f"Syncing [{name}] to format [{fmt}] in '{target_root}'...")

    if fmt == "github":
        dest_agent_dir = target_root / ".github" / "agents"
        dest_file = dest_agent_dir / f"{agent_slug}.md"
        skills_target_dir = target_root / ".github" / "skills"
    elif fmt == "claude":
        dest_agent_dir = target_root / ".claude" / "agents"
        dest_file = dest_agent_dir / f"{agent_slug}.md"
        skills_target_dir = target_root / ".claude" / "skills"
    elif fmt == "cursor":
        dest_rules_dir = target_root / ".cursor" / "rules"
        dest_agent_dir = target_root / ".cursor" / "agents"
        dest_file = dest_rules_dir / f"{agent_slug}.mdc"
        dest_agent_file = dest_agent_dir / f"{agent_slug}.md"
        skills_target_dir = target_root / ".cursor" / "skills"
    elif fmt == "gemini":
        dest_agent_dir = target_root / ".gemini" / "agents"
        dest_file = dest_agent_dir / f"{agent_slug}.md"
        skills_target_dir = target_root / ".gemini" / "skills"
    else:  # raw
        dest_agent_dir = target_root / "agents"
        dest_file = dest_agent_dir / f"{agent_slug}.md"
        skills_target_dir = target_root / "skills"

    if dry_run:
        log_pass(f"[DRY-RUN] Would create agent: {dest_file}")
    else:
        dest_agent_dir.mkdir(parents=True, exist_ok=True)
        if fmt == "cursor":
            dest_rules_dir.mkdir(parents=True, exist_ok=True)
            cursor_content = transform_for_cursor(meta, body)
            dest_file.write_text(cursor_content, encoding="utf-8")
            log_pass(f"Wrote Cursor Rule: {dest_file}")
            dest_agent_file.write_text(agent_path.read_text(encoding="utf-8"), encoding="utf-8")
            log_pass(f"Wrote Cursor Agent: {dest_agent_file}")
        elif use_symlink:
            if dest_file.exists() or dest_file.is_symlink():
                dest_file.unlink()
            rel_src = os.path.relpath(agent_path, dest_agent_dir)
            dest_file.symlink_to(rel_src)
            log_pass(f"Symlinked: {dest_file} -> {rel_src}")
        else:
            shutil.copy2(agent_path, dest_file)
            log_pass(f"Wrote Agent: {dest_file}")

    declared_skills = meta.get("skills", [])
    if sync_skills and declared_skills:
        log_info(f"Syncing {len(declared_skills)} linked skills for [{agent_slug}]...")
        for skill_rel in declared_skills:
            src_skill_path = skills_dir / skill_rel
            if not src_skill_path.exists():
                log_fail(f"Declared skill path does not exist: {src_skill_path}")
                continue

            dest_skill_path = skills_target_dir / skill_rel
            if dry_run:
                log_pass(f"[DRY-RUN] Would sync skill: {src_skill_path.name} -> {dest_skill_path}")
            elif use_symlink:
                dest_skill_path.parent.mkdir(parents=True, exist_ok=True)
                if dest_skill_path.exists() or dest_skill_path.is_symlink():
                    if dest_skill_path.is_dir() and not dest_skill_path.is_symlink():
                        shutil.rmtree(dest_skill_path)
                    else:
                        dest_skill_path.unlink()
                rel_src = os.path.relpath(src_skill_path, dest_skill_path.parent)
                dest_skill_path.symlink_to(rel_src)
                log_pass(f"Symlinked skill: {dest_skill_path.name} -> {rel_src}")
            else:
                dest_skill_path.parent.mkdir(parents=True, exist_ok=True)
                if dest_skill_path.exists():
                    shutil.rmtree(dest_skill_path)
                shutil.copytree(src_skill_path, dest_skill_path)
                log_pass(f"Copied skill: {src_skill_path.name} -> {dest_skill_path}")

    return True


def cmd_sync(args, asset_root: Path):
    """Sync agents and skills to the destination workspace."""
    agents_dir = get_agents_dir(asset_root)
    skills_dir = get_skills_dir(asset_root)
    available_agents = get_available_agents(agents_dir)

    target_root = Path(args.target).resolve()

    if args.all or args.agent == "all":
        targets = list(available_agents.keys())
    else:
        if args.agent not in available_agents:
            log_fail(f"Agent '{args.agent}' not found. Available: {', '.join(available_agents.keys())}")
            return 1
        targets = [args.agent]

    print("\n" + "=" * 65)
    print(" 🔄 Open Cloud Agents: Workspace Synchronizer")
    print("=" * 65)
    log_info(f"Target Directory: {target_root}")
    log_info(f"Target Format:    {args.format}")
    log_info(f"Sync Skills:      {args.sync_skills}")
    log_info(f"Use Symlinks:     {args.symlink}")
    log_info(f"Dry Run:          {args.dry_run}")
    print("-" * 65)

    success_count = 0
    for agent_slug in targets:
        agent_path = available_agents[agent_slug]
        if sync_single_agent(
            agent_slug=agent_slug,
            agent_path=agent_path,
            target_root=target_root,
            fmt=args.format,
            sync_skills=args.sync_skills,
            use_symlink=args.symlink,
            dry_run=args.dry_run,
            skills_dir=skills_dir,
        ):
            success_count += 1

    print("=" * 65)
    log_pass(f"Successfully synchronized {success_count} agent(s) into '{target_root}'\n")
    return 0


def cmd_validate(asset_root: Path):
    """Runs repository hygiene and agent pipeline validation."""
    log_info("Running Open Cloud Agents contract and spec validation...")
    overall_rc = 0
    py_bin = (
        shutil.which("python3") or shutil.which("python") or sys.executable
        if getattr(sys, "frozen", False)
        else sys.executable
    )

    # Prefer current working directory if it contains an Open Cloud Agents repo structure
    target_dir = str(Path.cwd()) if (Path.cwd() / "agents").is_dir() and (Path.cwd() / "skills").is_dir() else str(asset_root)

    pipeline_script = asset_root / "scripts" / "agents" / "agent_pipeline.py"
    if pipeline_script.exists():
        res = subprocess.run([py_bin, str(pipeline_script), "--validate", "--target", target_dir])
        if res.returncode != 0:
            overall_rc = res.returncode
    else:
        log_fail(f"Pipeline validation script not found at: {pipeline_script}")
        overall_rc = 1

    ci_script = asset_root / "scripts" / "ci" / "validate_repo.py"
    if ci_script.exists():
        res_ci = subprocess.run([py_bin, str(ci_script), target_dir])
        if res_ci.returncode != 0:
            overall_rc = res_ci.returncode

    return overall_rc


def cmd_run(args, asset_root: Path):
    """Runs the multi-agent pipeline simulation on a task."""
    py_bin = (
        shutil.which("python3") or shutil.which("python") or sys.executable
        if getattr(sys, "frozen", False)
        else sys.executable
    )
    pipeline_script = asset_root / "scripts" / "agents" / "agent_pipeline.py"
    if pipeline_script.exists():
        cmd = [py_bin, str(pipeline_script), "--task", args.task]
        if getattr(args, "export_json", None):
            cmd.extend(["--export-json", args.export_json])
        if getattr(args, "provider", None):
            cmd.extend(["--provider", args.provider])
        if getattr(args, "model", None):
            cmd.extend(["--model", args.model])
        res = subprocess.run(cmd)
        return res.returncode
    log_fail(f"Pipeline runner script not found at: {pipeline_script}")
    return 1


def cmd_learn(args, asset_root: Path):
    """Continual Learning Engine: Ingests an incident postmortem or runtime fact into AGENTS.md."""
    agents_md = asset_root / "AGENTS.md"
    if not agents_md.exists():
        agents_md = Path.cwd() / "AGENTS.md"

    if not agents_md.exists():
        log_fail("Could not locate AGENTS.md master directive.")
        return 1

    category = getattr(args, "category", None) or "CI/CD & Autonomous Agent Governance"
    fact_title = ""
    fact_body = ""

    if getattr(args, "incident", None):
        inc_path = Path(args.incident)
        if not inc_path.exists():
            log_fail(f"Incident report not found at: {inc_path}")
            return 1
        content = inc_path.read_text(encoding="utf-8")
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        title_candidate = lines[0].lstrip("#").strip() if lines else inc_path.stem
        fact_title = title_candidate
        fact_body = f"Incident postmortem finding from {inc_path.name}: " + " ".join(lines[1:4])
    elif getattr(args, "fact", None):
        raw_fact = args.fact.strip()
        if ":" in raw_fact:
            fact_title, fact_body = raw_fact.split(":", 1)
            fact_title = fact_title.strip()
            fact_body = fact_body.strip()
        else:
            fact_title = "Runtime Edge Case"
            fact_body = raw_fact
    else:
        log_fail("Please provide either --incident <path> or --fact 'Title: Description'.")
        return 1

    bullet = f"- **{fact_title}:** {fact_body}"
    print(f"\n🧠 \033[1mContinual Learning Ingestion\033[0m")
    print(f"   Category: {category}")
    print(f"   Entry:    {bullet}")

    if getattr(args, "dry_run", False):
        log_info("[Dry-Run] Preview completed. No files modified.")
        return 0

    agents_content = agents_md.read_text(encoding="utf-8")
    if fact_title in agents_content:
        log_info(f"Fact '{fact_title}' is already recorded in AGENTS.md. Skipping duplicate.")
        return 0

    category_header = f"### Learned {category} Facts"
    if category_header in agents_content:
        target_pos = agents_content.find(category_header) + len(category_header)
        new_content = agents_content[:target_pos] + "\n" + bullet + agents_content[target_pos:]
    else:
        marker = "## 🧠 Continual Learning Memory & Dynamic Knowledge Base"
        if marker in agents_content:
            target_pos = agents_content.find(marker) + len(marker)
            addition = f"\n\n{category_header}\n{bullet}"
            new_content = agents_content[:target_pos] + addition + agents_content[target_pos:]
        else:
            new_content = agents_content + f"\n\n{category_header}\n{bullet}\n"

    agents_md.write_text(new_content, encoding="utf-8")
    log_pass(f"Successfully recorded learned fact into {agents_md.name} under '{category}'.")
    log_info("Collaborative attribution required: git commit with Co-authored-by: Antigravity <antigravity@google.com>")
    return 0


def cmd_sandbox(args, asset_root: Path) -> int:
    """Ephemeral KinD Sandbox Engine: Automates multi-node testing for manifests, Helm, Kustomize, and incident scenarios."""
    sandbox_script = (
        asset_root
        / "skills"
        / "devops"
        / "kubernetes"
        / "k8s-kind-sandbox-testing"
        / "scripts"
        / "run_kind_sandbox.sh"
    )
    if not sandbox_script.exists():
        log_fail(f"KinD sandbox runner script not found at: {sandbox_script}")
        return 1

    # Check dependencies: kind, kubectl, docker
    missing = []
    for tool in ("docker", "kind", "kubectl"):
        if not shutil.which(tool):
            missing.append(tool)

    if missing:
        log_fail(f"Required binary/binaries missing on PATH: {', '.join(missing)}")
        log_info("Please ensure Docker, KinD, and kubectl are installed to run sandboxes.")
        return 1

    cmd = [str(sandbox_script)]
    if getattr(args, "manifest", None):
        cmd.extend(["--manifest", args.manifest])
    elif getattr(args, "helm", None):
        cmd.extend(["--helm", args.helm])
    elif getattr(args, "kustomize", None):
        cmd.extend(["--kustomize", args.kustomize])
    elif getattr(args, "scenario", None):
        cmd.extend(["--scenario", args.scenario])
    else:
        log_fail("Please specify one of: --manifest <path>, --helm <path>, --kustomize <path>, or --scenario <path>.")
        return 1

    if getattr(args, "cluster_name", None):
        cmd.extend(["--cluster-name", args.cluster_name])
    if getattr(args, "k8s_version", None):
        cmd.extend(["--k8s-version", args.k8s_version])
    if getattr(args, "ingress", False):
        cmd.append("--ingress")
    if getattr(args, "keep_cluster", False):
        cmd.append("--keep-cluster")

    res = subprocess.run(cmd)
    return res.returncode


def cmd_info(asset_root: Path):
    """Displays CLI and asset environment information."""
    print(f"\n{get_cli_header()}")
    print("=" * 60)
    print(f"Asset Home:        {asset_root}")
    print(f"Agents Directory:  {get_agents_dir(asset_root)}")
    print(f"Skills Directory:  {get_skills_dir(asset_root)}")
    print(f"Python Runtime:    {sys.executable} ({sys.version.split()[0]})")
    agents = get_available_agents(get_agents_dir(asset_root))
    print(f"Registered Agents: {len(agents)} active")
    print("=" * 60)
    return 0


def cmd_update(asset_root: Path):
    """Updates the ocagents CLI binary and canonical content catalog."""
    print(f"\n{get_cli_header()}")
    log_info("Checking for Open Cloud Agents CLI updates...")

    # 1. Check CLI binary release
    latest_info = fetch_latest_release(timeout=2.0)
    if latest_info:
        latest_ver = latest_info.get("latest_version", "")
        # Refresh cache file
        cache_file = get_update_cache_file()
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(latest_info), encoding="utf-8")
        except Exception:
            pass

        if parse_semver(latest_ver) > parse_semver(__version__):
            _, upgrade_cmd = detect_install_method()
            log_info(f"Newer CLI release available: v{__version__} → v{latest_ver}")
            print(f"   Run to upgrade: \033[36m{upgrade_cmd}\033[0m")
            print(f"   Release notes:  {latest_info.get('html_url')}\n")
        else:
            log_pass(f"CLI binary is up to date (v{__version__}).")
    else:
        log_info("Could not reach release registry; skipping binary version check.")

    # 2. Update local catalog
    target_dir = Path.home() / ".open-cloud-agents"
    print(f"\n☁️  Updating Open Cloud Agents catalog at: {target_dir}")
    if target_dir.exists() and (target_dir / ".git").exists():
        log_info("Fetching latest updates from git repository...")
        res = subprocess.run(["git", "-C", str(target_dir), "pull", "origin", "main"])
        if res.returncode == 0:
            log_pass("Successfully updated Open Cloud Agents catalog.")
            return 0
        log_fail("Git pull failed.")
        return 1
    else:
        log_info(f"Cloning canonical repository from {CANONICAL_REPO_URL}...")
        res = subprocess.run(["git", "clone", "--depth=1", CANONICAL_REPO_URL, str(target_dir)])
        if res.returncode == 0:
            log_pass("Successfully cloned Open Cloud Agents catalog.")
            return 0
        log_fail("Git clone failed.")
        return 1


def cmd_version():
    """Display CLI and framework version with architectural details."""
    print(f"\n{get_cli_header()}")
    print("   ─────────────────────────────────────────────────────────")
    print("   • Master Suite:       7 Specialist Personas (Aligned to Well-Architected)")
    print("   • Skills Ecosystem:   377+ 3-Tier Enterprise Runbooks")
    print("   • License:            Apache 2.0 (Open Source)")
    print("   • Canonical Catalog:  https://github.com/open-cloud-agents/ocagents")
    print("   • Documentation:      https://open-cloud-agents.github.io/ocagents/")
    print("   • Founding Architect: Ibrahim Jimoh (https://www.linkedin.com/in/ijimoh)")

    # Display update status from cache if available
    cache_file = get_update_cache_file()
    if cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            latest_ver = data.get("latest_version", "")
            if latest_ver and parse_semver(latest_ver) > parse_semver(__version__):
                _, upgrade_cmd = detect_install_method()
                print(f"   • Update Status:      \033[33mv{latest_ver} available\033[0m (run: \033[36m{upgrade_cmd}\033[0m)")
            elif latest_ver:
                print(f"   • Update Status:      \033[32mUp to date (v{__version__})\033[0m")
        except Exception:
            pass
    print()
    return 0


def cmd_findings(args, asset_root: Path) -> int:
    """Validates structured finding JSON documents against schemas/v1/finding.json and rule catalog."""
    from ocagents.findings import FindingValidator, resolve_default_repo_root

    raw_path = getattr(args, "path", ".")
    target_path = Path(raw_path) if raw_path else Path(".")
    if not target_path.exists():
        print(f"\033[31m✖ Error: Target path not found: {target_path}\033[0m")
        return 1

    diff_text = None
    if getattr(args, "diff", None):
        diff_p = Path(args.diff)
        if diff_p.is_file():
            diff_text = diff_p.read_text(encoding="utf-8", errors="replace")
        else:
            print(f"\033[31m✖ Error: Diff file not found: {diff_p}\033[0m")
            return 1

    repo_root = resolve_default_repo_root(
        explicit_root=getattr(args, "repo_root", None),
        target_path=target_path,
        asset_root=asset_root,
    )
    validator = FindingValidator(repo_root=repo_root)

    finding_files = []
    if target_path.is_file():
        finding_files = [target_path]
    elif target_path.is_dir():
        finding_files = sorted(target_path.glob("**/*.json"))

    if not finding_files:
        print(f"\033[33mℹ No JSON finding files found in {target_path}\033[0m")
        return 0

    print(f"\033[34mℹ Validating {len(finding_files)} finding document(s) against schemas/v1/finding.json...\033[0m")

    total_passed = 0
    total_failed = 0

    for f in finding_files:
        res = validator.validate_file(f, diff_text=diff_text)
        rel_name = f.name
        if res.is_valid:
            total_passed += 1
            print(f"  \033[32m✔ {rel_name}: Validated\033[0m (id: {res.finding_id}, rule: {res.rule_id}, status: {res.corroboration_status})")
        else:
            total_failed += 1
            print(f"  \033[31m✖ {rel_name}: Validation failed ({len(res.all_errors)} violation(s))\033[0m")
            for err in res.schema_errors:
                print(f"    - \033[31m[Schema Error]\033[0m {err}")
            for err in res.provenance_errors:
                print(f"    - \033[33m[Provenance Error]\033[0m {err}")

    if total_failed > 0:
        print(f"\n\033[31mFAILED: {total_failed} finding document(s) failed validation.\033[0m")
        return 1

    print(f"\n\033[32mSUCCESS: All {total_passed} finding document(s) conform to Finding Schema v1.0!\033[0m")
    return 0


def cmd_preflight(args, asset_root: Path) -> int:
    """Runs deterministic pre-flight checks and fail-closed availability gate across a changeset."""
    from ocagents.findings import resolve_default_repo_root
    from ocagents.scanner.availability import AvailabilityStatus
    from ocagents.scanner.preflight import PreflightEngine, PreflightResult

    repo_root = resolve_default_repo_root(
        explicit_root=getattr(args, "repo_root", None),
        asset_root=asset_root,
    )
    engine = PreflightEngine(
        repo_root=repo_root,
        signing_key=getattr(args, "signing_key", None),
        codeql_db_path=getattr(args, "codeql_db", None),
        codeql_query_suite=getattr(args, "codeql_suite", None),
    )

    try:
        changeset, diff_text = engine.resolve_changeset(
            paths=getattr(args, "paths", None),
            diff_target=getattr(args, "diff", None),
        )
    except (ValueError, FileNotFoundError) as err:
        err_result = PreflightResult(
            status=AvailabilityStatus.INCOMPLETE_CHECK_FAILED,
            exit_code=1,
            diagnostics=[f"FAIL-CLOSED: Diff resolution error: {err}"],
            strict=getattr(args, "strict", False),
        )
        if getattr(args, "json", False):
            print(json.dumps(err_result.to_dict(), indent=2))
        else:
            use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
            print(err_result.format_terminal_summary(use_color=use_color))
        return 1

    result = engine.run(
        changeset=changeset,
        diff_text=diff_text,
        strict=getattr(args, "strict", False),
    )

    if getattr(args, "json", False):
        print(json.dumps(result.to_dict(), indent=2))
    else:
        use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        print(result.format_terminal_summary(use_color=use_color))

    return result.exit_code


def cmd_triage(args, asset_root: Path) -> int:
    """Classifies a Git changeset into blast radius risk tiers (0-2) and determines agent roster."""
    from ocagents.triage import classify_changeset, classify_diff, classify_git_ref

    diff_path_or_ref = getattr(args, "diff", None)
    base_ref = getattr(args, "base", "main")
    head_ref = getattr(args, "head", "HEAD")
    emit_json = getattr(args, "json", False)
    repo_root = getattr(args, "repo_root", None) or os.getcwd()

    result = None
    if diff_path_or_ref:
        p = Path(diff_path_or_ref)
        if p.is_file():
            diff_text = p.read_text(encoding="utf-8", errors="replace")
            result = classify_diff(diff_text)
        else:
            try:
                result = classify_git_ref(base_ref=diff_path_or_ref, head_ref=head_ref, repo_root=repo_root)
            except (RuntimeError, subprocess.SubprocessError, OSError) as e:
                print(f"\033[31m✖ Error during git diff triage: {e}\033[0m")
                return 1
    else:
        try:
            result = classify_git_ref(base_ref=base_ref, head_ref=head_ref, repo_root=repo_root)
        except (RuntimeError, subprocess.SubprocessError, OSError):
            try:
                result = classify_git_ref(base_ref="HEAD~1", head_ref="HEAD", repo_root=repo_root)
            except (RuntimeError, subprocess.SubprocessError, OSError):
                diff_proc = subprocess.run(["git", "diff", "HEAD"], cwd=repo_root, capture_output=True, text=True, check=False)
                if diff_proc.returncode == 0 and diff_proc.stdout.strip():
                    result = classify_diff(diff_proc.stdout)
                else:
                    result = classify_changeset([])

    if emit_json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    print("============================================================")
    print(" 🛡️  Open Cloud Agents: Blast Radius Risk Triage (Stage 2)")
    print("============================================================")
    tier_colors = {0: "\033[32m", 1: "\033[34m", 2: "\033[31m"}
    color = tier_colors.get(result.risk_tier, "\033[33m")
    print(f"Changeset Risk Tier: {color}{result.tier_name}\033[0m")
    print(f"Activated Roster:     {len(result.activated_agents)} specialist agent(s)")
    if result.activated_agents:
        for a in result.activated_agents:
            print(f"  • {a}")
    else:
        print("  • (None: LLM review bypassed for docs/non-code assets)")

    print("\nChanged Files Breakdown:")
    print(f"  • Total Modified Files: {result.diff_summary['total_files']}")
    print(f"  • Tier 0 (Docs/Assets): {result.diff_summary['tier_0']}")
    print(f"  • Tier 1 (App Logic):   {result.diff_summary['tier_1']}")
    print(f"  • Tier 2 (Infra/IaC):   {result.diff_summary['tier_2']}")

    if result.reasons:
        print("\nPrimary Triage Drivers:")
        for r in result.reasons[:6]:
            print(f"  {r}")
    print("============================================================")
    return 0


def cmd_store(args, asset_root: Path) -> int:
    """Inspects, queries, and exports findings from the local Blackboard storage."""
    import sqlite3

    from ocagents.blackboard.projections import (
        project_findings_minified_json,
        project_findings_toon,
    )
    from ocagents.blackboard.store import DEFAULT_DB_PATH, BlackboardStore

    action = getattr(args, "store_action", "list") or "list"
    db_path = getattr(args, "db", None) or DEFAULT_DB_PATH
    emit_json = getattr(args, "json", False)

    try:
        store = BlackboardStore(db_path)
    except (sqlite3.Error, OSError, ValueError) as e:
        print(f"\033[31m✖ Error connecting to Blackboard database at {db_path}: {e}\033[0m")
        return 1

    with store:
        if action == "list":
            run_id = getattr(args, "run_id", None)
            severity = getattr(args, "severity", None)
            origin = getattr(args, "origin", None)

            if run_id:
                findings = store.get_findings(run_id=run_id, severity=severity, origin=origin)
                if emit_json:
                    print(json.dumps(findings, indent=2))
                else:
                    print(f"\033[34mℹ Blackboard findings for run_id: {run_id} ({len(findings)} finding(s))\033[0m\n")
                    print(project_findings_toon(findings))
            else:
                runs = store.list_runs(limit=20)
                if emit_json:
                    print(json.dumps(runs, indent=2))
                else:
                    print("============================================================")
                    print(f" 🗄️  Open Cloud Agents: Blackboard Runs ({len(runs)} recent)")
                    print("============================================================")
                    if not runs:
                        print("  (No recorded audit runs in blackboard store)")
                    for r in runs:
                        rid = r.get("run_id", "unknown")
                        tier = r.get("risk_tier", "-")
                        commit = (r.get("commit_sha") or "")[:8]
                        ts = r.get("timestamp_utc", "")
                        f_count = len(store.get_findings(run_id=rid))
                        print(f"  • {rid} | Tier {tier} | commit:{commit} | findings:{f_count} | {ts}")
                    print("============================================================")
            return 0

        elif action == "export":
            run_id = getattr(args, "run_id", None)
            if not run_id:
                print("\033[31m✖ Error: --run-id is required for export\033[0m")
                return 1

            fmt = getattr(args, "format", "toon")
            findings = store.get_findings(run_id=run_id)
            if fmt == "json":
                out_content = json.dumps(findings, indent=2)
            elif fmt == "minified":
                out_content = project_findings_minified_json(findings)
            elif fmt in ("markdown", "md", "summary"):
                from ocagents.reporting.synthesis import generate_markdown_report

                envelope = store.get_run(run_id)
                executions = store.get_executions(run_id)
                run_summary = {
                    "run_id": run_id,
                    "agent_results": {
                        e["agent"]: {
                            "status": e["status"],
                            "findings_count": len([f for f in findings if f.get("agent") == e["agent"]]),
                            "prompt_tokens": e["prompt_tokens"],
                            "completion_tokens": e["output_tokens"],
                            "total_tokens": e["prompt_tokens"] + e["output_tokens"],
                            "duration_ms": e["duration_ms"],
                        }
                        for e in executions
                    },
                    "total_tokens_consumed": sum(e["prompt_tokens"] + e["output_tokens"] for e in executions),
                    "execution_time_seconds": sum(e["duration_ms"] for e in executions) / 1000.0,
                    "agents_activated": list({e["agent"] for e in executions}),
                }
                out_content = generate_markdown_report(
                    findings=findings,
                    run_envelope=envelope,
                    run_summary=run_summary,
                )
            else:
                out_content = project_findings_toon(findings)

            out_file = getattr(args, "out", None)
            if out_file:
                p = Path(out_file)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(out_content, encoding="utf-8")
                print(f"\033[32m✔ Exported {len(findings)} finding(s) to {out_file} (format: {fmt})\033[0m")
            else:
                print(out_content)
            return 0

        elif action == "prune":
            keep = getattr(args, "keep", 20)
            deleted = store.prune_runs(keep_last=keep)
            print(f"\033[32m✔ Pruned {deleted} historical run(s) from blackboard (kept last {keep})\033[0m")
            return 0

        elif action == "info":
            runs = store.list_runs(limit=1000)
            total_findings = len(store.get_findings())
            info_dict = {
                "db_path": str(db_path),
                "total_runs": len(runs),
                "total_findings": total_findings,
            }
            if emit_json:
                print(json.dumps(info_dict, indent=2))
            else:
                print("============================================================")
                print(" 🗄️  Open Cloud Agents: Blackboard Store Status")
                print("============================================================")
                print(f"Database Location: {db_path}")
                print(f"Total Audit Runs:  {len(runs)}")
                print(f"Total Findings:    {total_findings}")
                print("============================================================")
            return 0

    return 0


def cmd_report(args, asset_root: Path) -> int:
    """Compiles structured findings into a user-facing Markdown review summary."""
    from ocagents.blackboard.store import DEFAULT_DB_PATH, BlackboardStore
    from ocagents.reporting.synthesis import generate_markdown_report

    run_id = getattr(args, "run_id", None)
    db_path = getattr(args, "db", None) or DEFAULT_DB_PATH
    out_format = getattr(args, "format", "markdown") or "markdown"
    out_file = getattr(args, "out", None)
    repo_url = getattr(args, "repo_url", None)

    findings_file = getattr(args, "file", None)
    if findings_file:
        p = Path(findings_file)
        if not p.is_file():
            print(f"\033[31m✖ Error: Findings file not found: {p}\033[0m")
            return 1
        try:
            findings_data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"\033[31m✖ Error parsing JSON findings file: {e}\033[0m")
            return 1
        if isinstance(findings_data, dict) and "findings" in findings_data:
            findings = findings_data["findings"]
        elif isinstance(findings_data, list):
            findings = findings_data
        else:
            findings = [findings_data]
        envelope = None
        run_summary = None
    else:
        try:
            store = BlackboardStore(db_path)
        except Exception as e:
            print(f"\033[31m✖ Error opening blackboard store at {db_path}: {e}\033[0m")
            return 1

        with store:
            if not run_id:
                recent_runs = store.list_runs(limit=1)
                if not recent_runs:
                    print(f"\033[33mℹ No runs found in blackboard database at {db_path}\033[0m")
                    return 0
                run_id = recent_runs[0].get("run_id")

            envelope = store.get_run(run_id)
            findings = store.get_findings(run_id=run_id)
            executions = store.get_executions(run_id=run_id)
            run_summary = {
                "run_id": run_id,
                "agent_results": {
                    e["agent"]: {
                        "status": e["status"],
                        "findings_count": len([f for f in findings if f.get("agent") == e["agent"]]),
                        "prompt_tokens": e["prompt_tokens"],
                        "completion_tokens": e["output_tokens"],
                        "total_tokens": e["prompt_tokens"] + e["output_tokens"],
                        "duration_ms": e["duration_ms"],
                    }
                    for e in executions
                },
                "total_tokens_consumed": sum(e["prompt_tokens"] + e["output_tokens"] for e in executions),
                "execution_time_seconds": sum(e["duration_ms"] for e in executions) / 1000.0,
                "agents_activated": list({e["agent"] for e in executions}),
            }

    if out_format == "json":
        report_content = json.dumps(
            {
                "findings": findings,
                "envelope": envelope.to_dict() if envelope else None,
                "summary": run_summary,
            },
            indent=2,
        )
    else:
        report_content = generate_markdown_report(
            findings=findings,
            run_envelope=envelope,
            run_summary=run_summary,
            repo_url=repo_url,
        )

    if out_file:
        out_p = Path(out_file)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(report_content, encoding="utf-8")
        print(f"\033[32m✔ Verification summary report written to {out_file}\033[0m")
    else:
        print(report_content)

    return 0


def cmd_help(subcommand: str | None = None) -> int:
    """Render comprehensive, beautifully formatted command guides with real-world examples."""
    sub = (subcommand or "").lower().strip()

    if sub in ("list", "ls", "agents"):
        print("""
☁️  \033[1mocagents list\033[0m: Master Suite Agent & Skills Registry

\033[1mDESCRIPTION:\033[0m
  Inspect all 7 specialist agents in the Master Suite, their operational mandates,
  declared tool boundaries (read, search, edit, execute, web), and linked skills.

\033[1mUSAGE:\033[0m
  ocagents list
  ocagents ls
  ocagents -agents list
  ocagents -a ls

\033[1mEXAMPLES:\033[0m
  # Standard list of all agents and their linked specialist skills
  ocagents list

  # Quick shorthand invocation
  ocagents -a ls

  # Compatible flag syntax
  ocagents -agents list
""")
        return 0

    if sub == "sync":
        print("""
☁️  \033[1mocagents sync\033[0m: Universal Workspace Synchronizer

\033[1mDESCRIPTION:\033[0m
  Exports and synchronizes Open Cloud Agents specialist personas and 3-tier skills
  directly into your target repository workspace for GitHub Copilot, Claude Code,
  Cursor, Gemini, or raw custom agent orchestrators.

\033[1mUSAGE:\033[0m
  ocagents sync [AGENT_SLUG] [options]
  ocagents -A -format <FORMAT> --target <DIR>

\033[1mTARGET FORMATS (-f, -format, --format):\033[0m
  • github   Synchronizes to .github/agents/ and .github/skills/ (GitHub Copilot / VS Code)
  • claude   Synchronizes to .claude/agents/ and .claude/skills/ (Claude Code)
  • cursor   Converts to Cursor Rules (.cursor/rules/*.mdc) and .cursor/agents/
  • gemini   Synchronizes to .gemini/agents/ and .gemini/skills/ (Antigravity IDE / Gemini)
  • raw      Synchronizes directly to agents/ and skills/ in target directory

\033[1mOPTIONS:\033[0m
  -A, --all              Sync all 7 Master Suite agents at once
  -f, --format FORMAT    Target format: github, claude, cursor, gemini, raw (default: github)
  -t, --target DIR       Target repository path (default: current directory '.')
  -s, --sync-skills      Also synchronize all specialist execution skills linked to agent
  --symlink              Create relative symlinks instead of copying full files
  --dry-run              Preview planned file creations without writing changes to disk

\033[1mREAL-WORLD EXAMPLES:\033[0m
  # 1. Sync all 7 agents for GitHub Copilot (.github/agents/):
  ocagents -A -format github --target /path/to/my-repo

  # 2. Sync DevSecOps Reviewer + its 9 declared skills for Claude Code:
  ocagents sync devsecops-reviewer --format claude --target . --sync-skills

  # 3. Export all 7 agents into Cursor Rules (.cursor/rules/*.mdc):
  ocagents sync -A --format cursor --target /path/to/my-repo

  # 4. Dry-run preview: see what files would be created without touching disk:
  ocagents sync -A --format github --target . --dry-run

  # 5. Fast development: symlink agents directly to local catalog:
  ocagents sync -A --format claude --target . --symlink
""")
        return 0

    if sub in ("validate", "check"):
        print("""
☁️  \033[1mocagents validate\033[0m: Agent Contract & Repository Hygiene Validation

\033[1mDESCRIPTION:\033[0m
  Executes comprehensive multi-layer automated validation across all agent specifications,
  skill frontmatter, security guardrails, and repository hygiene invariants.

\033[1mVALIDATION SUITE PHASES:\033[0m
  1. Agent Spec & Boundaries:  YAML frontmatter, tool boundaries, system prompt token budgets.
  2. Enterprise Skills Audit:  YAML frontmatter compliance on all 377+ SKILL.md runbooks.
  3. Zero-Trust Security:      Scans for leaked local developer paths (/Users/<username>/).
  4. Repository Hygiene:       Checks executable script bits (+x), internal Markdown link integrity,
                               and scans for Trojan Source invisible unicode confusables.

\033[1mUSAGE:\033[0m
  ocagents validate
  ocagents check

\033[1mEXAMPLES:\033[0m
  # Run full automated validation suite:
  ocagents validate
""")
        return 0

    if sub in ("run", "simulate"):
        print("""
☁️  \033[1mocagents run\033[0m: Autonomous Multi-Agent Pipeline Simulator

\033[1mDESCRIPTION:\033[0m
  Simulates a real-world architectural design, review, and incident triage task
  through the 7-Agent Master Suite pipeline, exercising the handoff contracts between:
  1. Principal Cloud Architect ➔ 2. Security Compliance Commander ➔ 3. DevSecOps Reviewer ➔
  4. DevSecOps Engineer ➔ 5. SRE Reliability Engineer ➔ 6. FinOps Cost Optimizer ➔
  7. GitOps Release Manager.

\033[1mUSAGE:\033[0m
  ocagents run [TASK_DESCRIPTION]
  ocagents run --task "TASK_DESCRIPTION"

\033[1mEXAMPLES:\033[0m
  # Multi-region payment disaster recovery simulation:
  ocagents run --task "Architect multi-region payment DR failover with Aurora Global Database"

  # Zero-trust Kubernetes ingress audit simulation:
  ocagents run "Design zero-trust Kubernetes ingress with Cilium eBPF and Cloud Armor WAF"
""")
        return 0

    if sub in ("update", "upgrade"):
        print("""
☁️  \033[1mocagents update\033[0m: Catalog Synchronization & Update Channeling

\033[1mDESCRIPTION:\033[0m
  Pulls the latest canonical Open Cloud Agents catalog (agents, skills, rules)
  directly from GitHub into your local installation directory (~/.open-cloud-agents).

\033[1mUSAGE:\033[0m
  ocagents update
  ocagents upgrade

\033[1mSTREAMLINED UPDATE CHANNELS BY PLATFORM:\033[0m
  • Catalog Auto-Sync (Fastest):
      ocagents update

  • macOS & Linux (Homebrew):
      brew update && brew upgrade ocagents

  • Python / pipx (Universal):
      pipx upgrade open-cloud-agents

  • Windows (Winget):
      winget upgrade OpenCloudAgents.ocagents

  • Windows (Chocolatey):
      choco upgrade ocagents

  • Debian / Ubuntu (APT):
      sudo apt update && sudo apt install --only-upgrade ocagents

  • Alpine Linux (APK):
      apk update && apk upgrade ocagents

  • One-Liner Re-Run (macOS/Linux):
      curl -fsSL https://open-cloud-agents.github.io/ocagents/install.sh | bash
""")
        return 0

    if sub in ("info", "status", "env"):
        print("""
☁️  \033[1mocagents info\033[0m: Environment, Asset Catalog & Runtime Status

\033[1mDESCRIPTION:\033[0m
  Displays the active installation directory, resolved agent/skill catalog paths,
  detected Python runtime environment, and number of registered active agents.

\033[1mUSAGE:\033[0m
  ocagents info

\033[1mEXAMPLES:\033[0m
  ocagents info
""")
        return 0

    if sub in ("learn", "postmortem", "ingest"):
        print("""
☁️  \033[1mocagents learn\033[0m: Continual Learning & Postmortem Knowledge Ingestion

\033[1mDESCRIPTION:\033[0m
  Ingests incident postmortems, SRE post-incident reviews (PIRs), or newly discovered
  runtime edge cases directly into the persistent AGENTS.md Dynamic Knowledge Base.

\033[1mUSAGE:\033[0m
  ocagents learn --fact "Title: Detailed description and remediation."
  ocagents learn --incident <PATH_TO_POSTMORTEM_MD> [--category <CATEGORY>]

\033[1mEXAMPLES:\033[0m
  # Ingest a learned fact into Kubernetes Networking:
  ocagents learn --fact "CoreDNS UDP Throttling: Use ndots: 2 to prevent 5s latency spikes." --category "Kubernetes Networking"

  # Preview ingestion from postmortem without modifying files:
  ocagents learn --incident postmortems/inc-042.md --dry-run
""")
        return 0

    if sub in ("sandbox", "test-k8s", "kind"):
        print("""
☁️  \033[1mocagents sandbox\033[0m: Ephemeral KinD Sandbox Testing Engine

\033[1mDESCRIPTION:\033[0m
  Spins up an isolated, ephemeral multi-node Kubernetes-in-Docker (KinD) cluster
  to execute server-side dry runs, Helm chart installations, Kustomize validations,
  and live incident/failure scenario testing without touching live clusters.

\033[1mUSAGE:\033[0m
  ocagents sandbox [--manifest <PATH> | --helm <PATH> | --kustomize <PATH> | --scenario <PATH>] [options]

\033[1mTARGET MODES:\033[0m
  • --manifest, --manifests PATH   Validate raw YAML manifests or directory
  • --helm, --helm-chart PATH      Lint and install Helm chart release
  • --kustomize PATH               Build and apply Kustomize overlay
  • --scenario PATH                Deploy live incident failure scenario for agent triage

\033[1mOPTIONS:\033[0m
  --cluster-name NAME              Custom KinD cluster name
  --k8s-version VER                Kubernetes version tag (e.g. v1.31.0, v1.30.2, v1.29.4)
  --ingress                        Deploy ingress-nginx controller and map host ports 80/443
  --keep-cluster                   Retain the KinD cluster after execution for interactive triage

\033[1mEXAMPLES:\033[0m
  # 1. Ephemeral dry-run and apply of manifests:
  ocagents sandbox --manifests ./deploy/k8s/

  # 2. Test a Helm chart across Kubernetes v1.30:
  ocagents sandbox --helm ./charts/billing-api --k8s-version v1.30.2

  # 3. Deploy an incident scenario and keep cluster running for agent triage:
  ocagents sandbox --scenario scenarios/billing-service-outage --keep-cluster
""")
        return 0

    elif sub in ("preflight", "gate", "pre-flight"):
        print("""
🛡️  \033[1mocagents preflight\033[0m: Deterministic Pre-Flight Gatekeeper & Scanner Runner (v1.5+)

\033[1mDESCRIPTION:\033[0m
  Runs deterministic pre-flight checks across a target changeset in accordance with ADR-002:
  - Enforces fail-closed scanner availability protocol (halts before LLM review if required tool is missing)
  - Enforces signed exceptions manifest (.ocagents/exceptions.json) with strict 90-day lifespans
  - Executes OPA / institutional policy evaluation (Rule 01: Destructive Actions & Rule 04: Well-Architected)
  - Screens unified git diffs for destructive actions, state replacement, and unrestricted ingress
  - Returns exit code 0 on clean pass, 1 on required check failure / invariant defect, 2 on advisory warnings

\033[1mUSAGE:\033[0m
  ocagents preflight [PATHS...] [--diff [BASE_REF]] [--strict] [--json]

\033[1mOPTIONS:\033[0m
  PATHS                     Target file(s), directories, or globs to inspect
  --diff [BASE_REF]         Evaluate changed files from git diff (default: main) or diff patch file
  --strict                  Escalate advisory warnings and missing advisory tools to exit code 1
  --json                    Emit structured machine-readable JSON execution report
  --repo-root PATH          Custom repository root path for exceptions manifest and rule resolution

\033[1mEXAMPLES:\033[0m
  # 1. Inspect working tree changes before commit:
  ocagents preflight

  # 2. Evaluate pull request git diff against main:
  ocagents preflight --diff

  # 3. Evaluate pull request git diff against origin/main:
  ocagents preflight --diff origin/main

  # 4. Evaluate against a saved patch file:
  ocagents preflight --diff pr_patch.diff

  # 5. Evaluate specific IaC and Kubernetes manifests:
  ocagents preflight infra/main.tf k8s/deployment.yaml

  # 6. Strict CI quality gate mode (escalates advisory warnings to exit code 1):
  ocagents preflight --diff --strict

  # 7. Structured JSON report for CI pipelines:
  ocagents preflight --diff --json
""")
        return 0

    if sub in ("triage", "blast-radius"):
        print("""
☁️  \033[1mocagents triage\033[0m: Blast Radius Risk Tier Classifier & Agent Roster
 
\033[1mDESCRIPTION:\033[0m
  Evaluates git changesets and categorizes them into 3 operational risk tiers (ADR-002):
  • Tier 0: Documentation & Non-Code Assets (LLM Bypass, 0 tokens)
  • Tier 1: Application Logic Only (Routes exclusively to DevSecOps Reviewer)
  • Tier 2: High Blast Radius Infrastructure (Activates Master Suite Blackboard)

\033[1mUSAGE:\033[0m
  ocagents triage [--diff [DIFF_OR_REF]] [--base BASE] [--head HEAD] [--json]

\033[1mOPTIONS:\033[0m
  --diff [TARGET]           Path to unified diff file or base git ref (default: main)
  --base BASE               Base ref for git diff comparison (default: main)
  --head HEAD               Head ref for git diff comparison (default: HEAD)
  --json                    Emit structured machine-readable JSON report
  --repo-root PATH          Custom repository root path

\033[1mEXAMPLES:\033[0m
  # 1. Triage current working tree / branch against main:
  ocagents triage

  # 2. Triage against a specific base branch or PR patch:
  ocagents triage --diff origin/main
  ocagents triage --diff patch.diff

  # 3. Structured JSON output for CI pipeline routing:
  ocagents triage --json
""")
        return 0

    if sub in ("store", "findings-store"):
        print("""
☁️  \033[1mocagents store\033[0m: Local Blackboard Findings & Audit State Store

\033[1mDESCRIPTION:\033[0m
  Inspect, query, and export findings from the SQLite WAL Blackboard findings store.
  Supports deterministic deduplication tracking and TOON tabular export.

\033[1mACTIONS:\033[0m
  list                      List recorded runs or findings for a specific run
  export                    Export findings in JSON or TOON tabular format
  prune                     Prune historical runs and cascaded records
  info                      Display database path and summary metrics

\033[1mUSAGE:\033[0m
  ocagents store list [--run-id RUN_ID] [--severity SEV] [--json]
  ocagents store export --run-id RUN_ID [--format json|toon|minified] [--out FILE]
  ocagents store prune [--keep N]
  ocagents store info [--json]

\033[1mEXAMPLES:\033[0m
  # 1. List recent audit runs:
  ocagents store list

  # 2. List all findings for a specific run:
  ocagents store list --run-id run-019318b4-9a4f-7c1a

  # 3. Export findings as compact TOON table:
  ocagents store export --run-id run-019318b4-9a4f-7c1a --format toon

  # 4. Export findings as JSON file:
  ocagents store export --run-id run-019318b4-9a4f-7c1a --format json --out findings.json
""")
        return 0

    # Default Top-Level Help Guide
    print(f"""
{get_cli_header()}
AI-Powered Cloud Architecture & Security Review Framework

\033[1mUSAGE:\033[0m
  ocagents <subcommand> [options]
  oca <subcommand> [options]

\033[1mCORE SUBCOMMANDS:\033[0m
  \033[1mlist, ls\033[0m           List all 7 master suite specialist agents and linked skills
  \033[1msync\033[0m               Synchronize agents & skills into your repository workspace
  \033[1mvalidate, check\033[0m    Run complete spec validation, rule verification & repo hygiene
  \033[1mpreflight, gate\033[0m    Run deterministic pre-flight checks and fail-closed scanner gate
  \033[1mtriage\033[0m             Classify Git changeset into blast radius risk tiers (0-2) and roster
  \033[1mstore\033[0m              Inspect, query, and export Blackboard findings store
  \033[1mrun\033[0m                Simulate multi-agent design & review pipeline on a prompt
  \033[1mlearn\033[0m              Ingest runtime edge case or incident postmortem into AGENTS.md
  \033[1msandbox, kind\033[0m      Run ephemeral KinD sandbox verification on manifests, Helm, or scenarios
  \033[1minfo\033[0m               Display local asset catalog path, registered agents & runtime
  \033[1mupdate, upgrade\033[0m    Pull latest canonical agent & skill updates from GitHub
  \033[1mversion, -v\033[0m        Display CLI and agent framework version details
  \033[1mhelp, -h\033[0m           Show this command guide or detailed help on a subcommand

\033[1mQUICK-START SHORTCUTS:\033[0m
  \033[36mocagents -agents list\033[0m                     List all agents & declared skills
  \033[36mocagents -a ls\033[0m                            Short alias to list registered agents
  \033[36mocagents -A -format github --target .\033[0m     Sync all 7 agents for GitHub Copilot
  \033[36mocagents sync devsecops-reviewer -s\033[0m       Sync reviewer + 9 skills for Claude Code
  \033[36mocagents sync -A -f cursor --target .\033[0m     Sync all agents as Cursor Rules (.mdc)
  \033[36mocagents validate\033[0m                         Validate all agent specs & contracts
  \033[36mocagents update\033[0m                           Pull latest canonical agents catalog
  \033[36mocagents learn --fact "Fact: Details"\033[0m     Ingest learned runtime edge case
  \033[36mocagents sandbox --manifests ./k8s/\033[0m       Ephemeral KinD manifest dry-run test

\033[1mDETAILED SUBCOMMAND GUIDES:\033[0m
  Run \033[1mocagents help <subcommand>\033[0m or \033[1mocagents <subcommand> --help\033[0m for deep-dive examples:
    • \033[34mocagents help sync\033[0m       Workspace sync guides for Copilot, Claude, Cursor, Gemini
    • \033[34mocagents help list\033[0m       Registry listing and inspection options
    • \033[34mocagents help validate\033[0m   Validation, CIS audit and hygiene test options
    • \033[34mocagents help run\033[0m        Multi-agent pipeline simulation guides
    • \033[34mocagents help learn\033[0m      Continual learning ingestion guides
    • \033[34mocagents help sandbox\033[0m    Ephemeral KinD cluster testing guides
    • \033[34mocagents help update\033[0m     Cross-platform package update channeling workflows
""")
    return 0


def normalize_custom_args(argv: list[str]) -> list[str]:
    """Translates user-friendly short flags like -agents, -format, -target into standard flags."""
    normalized = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-format", "--format"):
            normalized.append("--format")
        elif arg in ("-target", "--target"):
            normalized.append("--target")
        elif arg in ("-version", "--version"):
            normalized.append("--version")
        elif arg in ("-help", "--help"):
            normalized.append("--help")
        elif arg == "-agents":
            normalized.append("agents")
        elif arg == "ls":
            normalized.append("list")
        elif arg in ("findings", "finding") and i + 1 < len(argv) and argv[i + 1] == "validate":
            normalized.append("findings")
            i += 1  # Skip redundant 'validate' token
        elif arg in ("findings", "finding") and i + 1 < len(argv) and argv[i + 1] == "store":
            normalized.append("store")
            i += 1  # Route to store subcommand
        else:
            normalized.append(arg)
        i += 1
    return normalized


def main():
    atexit.register(notify_update_if_available)
    init_background_update_check()

    raw_args = sys.argv[1:]

    # 1. Version queries: -v, -version, --version, version
    if len(raw_args) == 1 and raw_args[0] in ("-v", "-version", "--version", "version"):
        sys.exit(cmd_version())

    # 2. Top-level Help queries: -h, -help, --help, help
    if not raw_args or (len(raw_args) == 1 and raw_args[0] in ("-h", "-help", "--help", "help")):
        sys.exit(cmd_help(None))

    # 3. Subcommand Help queries: e.g. ocagents help sync, ocagents sync -h, ocagents sync -help
    if raw_args[0] in ("help", "-h", "-help", "--help") and len(raw_args) >= 2:
        sys.exit(cmd_help(raw_args[1]))

    KNOWN_SUBCOMMANDS = (
        "list",
        "ls",
        "sync",
        "validate",
        "check",
        "preflight",
        "gate",
        "pre-flight",
        "triage",
        "store",
        "findings-store",
        "findings",
        "finding",
        "run",
        "simulate",
        "learn",
        "postmortem",
        "ingest",
        "sandbox",
        "test-k8s",
        "kind",
        "info",
        "status",
        "env",
        "update",
        "upgrade",
    )
    if raw_args[0] in KNOWN_SUBCOMMANDS:
        for arg in raw_args[1:]:
            if arg in ("-h", "-help", "--help", "help"):
                sys.exit(cmd_help(raw_args[0]))

    # 4. Handle quick top-level invocations matching user request:
    # e.g.: ocagents -agents list, ocagents -a ls, ocagents agents list
    if len(raw_args) >= 1 and raw_args[0] in ("-agents", "agents", "-a") and len(raw_args) >= 2 and raw_args[1] in ("list", "ls"):
        raw_args = ["list"]
    elif len(raw_args) >= 1 and raw_args[0] in ("-a", "ls"):
        if len(raw_args) == 1 and raw_args[0] in ("ls", "list"):
            raw_args = ["list"]

    # 5. Handle shortcut: ocagents -A -format github --target /path
    if len(raw_args) >= 1 and raw_args[0] == "-A":
        raw_args = ["sync", "--all"] + raw_args[1:]

    normalized_args = normalize_custom_args(raw_args)

    parser = argparse.ArgumentParser(
        prog="ocagents",
        description="Open Cloud Agents: Universal CLI for Cloud Architecture & Security Review Agents.",
        add_help=False,  # Custom rich help handler
    )
    parser.add_argument("-v", "--version", action="store_true", help="Show version details")
    parser.add_argument("-h", "--help", action="store_true", help="Show help guide")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # list
    p_list = subparsers.add_parser("list", aliases=["ls"], help="List all 7 master suite agents and linked skills")

    # sync
    p_sync = subparsers.add_parser("sync", help="Synchronize agents & skills into your workspace")
    p_sync.add_argument("agent", nargs="?", default="devsecops-reviewer", help="Agent slug (or all)")
    p_sync.add_argument("-A", "--all", action="store_true", help="Sync all 7 agents")
    p_sync.add_argument("-a", dest="agent_opt", help="Agent slug alias")
    p_sync.add_argument("-f", "--format", choices=AVAILABLE_FORMATS, default="github", help="Target format")
    p_sync.add_argument("-t", "--target", default=".", help="Target directory")
    p_sync.add_argument("-s", "--sync-skills", action="store_true", help="Also sync declared specialist skills")
    p_sync.add_argument("--symlink", action="store_true", help="Use symlinks instead of copying")
    p_sync.add_argument("--dry-run", action="store_true", help="Dry run without writing files")

    # validate
    subparsers.add_parser("validate", aliases=["check"], help="Validate agent specs, tools, and repo hygiene")

    # preflight (v1.5+)
    p_preflight = subparsers.add_parser(
        "preflight",
        aliases=["gate", "pre-flight"],
        help="Run deterministic pre-flight checks and fail-closed scanner availability gate (v1.5+)",
    )
    p_preflight.add_argument(
        "paths",
        nargs="*",
        default=[],
        help="Target file(s), directories, or globs to inspect",
    )
    p_preflight.add_argument(
        "--diff",
        nargs="?",
        const="main",
        default=None,
        help="Evaluate changed files from git diff (optionally specifying base ref, e.g. --diff origin/main, or diff file)",
    )
    p_preflight.add_argument(
        "--strict",
        action="store_true",
        help="Enforce strict mode: escalate advisory warnings and missing advisory tools to exit code 1",
    )
    p_preflight.add_argument(
        "--json",
        action="store_true",
        help="Emit structured machine-readable JSON execution report",
    )
    p_preflight.add_argument(
        "--repo-root",
        help="Custom repository root path for exceptions manifest and rule catalog resolution",
    )
    p_preflight.add_argument(
        "--signing-key",
        help="Custom HMAC signing key for authenticating exception records (or set OCAGENTS_SIGNATURE_KEY)",
    )
    p_preflight.add_argument(
        "--codeql-db",
        help="Path to CodeQL database directory for SAST analysis (or set CODEQL_DB_PATH)",
    )
    p_preflight.add_argument(
        "--codeql-suite",
        default=None,
        help="CodeQL query suite or query pack to analyze (default: python-security-and-quality.qls or set CODEQL_QUERY_SUITE)",
    )

    # findings (v1.4+)
    p_findings = subparsers.add_parser("findings", aliases=["finding"], help="Validate and inspect machine-readable finding contracts (v1.4+)")
    p_findings.add_argument("path", nargs="?", default=".", help="Path to finding JSON document or directory of findings")
    p_findings.add_argument("--diff", help="Optional path to unified diff file for diff anchor corroboration")
    p_findings.add_argument("--repo-root", help="Custom repository root for rule catalog and repo anchor resolution")

    # triage (v1.6+)
    p_triage = subparsers.add_parser("triage", help="Classify Git changeset into blast radius risk tiers (0-2) and roster (v1.6+)")
    p_triage.add_argument("--diff", help="Optional path to unified diff file or base git ref")
    p_triage.add_argument("--base", default="main", help="Base reference for git diff comparison (default: main)")
    p_triage.add_argument("--head", default="HEAD", help="Head reference for git diff comparison (default: HEAD)")
    p_triage.add_argument("--json", action="store_true", help="Emit structured machine-readable JSON triage report")
    p_triage.add_argument("--repo-root", help="Custom repository root path")

    # store (v1.6+)
    p_store = subparsers.add_parser("store", aliases=["findings-store"], help="Inspect, query, and export Blackboard findings store (v1.6+)")
    p_store_sub = p_store.add_subparsers(dest="store_action", help="Store action (list, export, prune, info)")

    p_store_list = p_store_sub.add_parser("list", help="List findings or runs from blackboard store")
    p_store_list.add_argument("--run-id", help="Filter findings by specific run_id")
    p_store_list.add_argument("--severity", choices=["critical", "high", "medium", "low"], help="Filter by severity")
    p_store_list.add_argument("--origin", help="Filter by origin (deterministic_linter, model_assertion)")
    p_store_list.add_argument("--db", help="Path to SQLite database (default: .ocagents/blackboard.db)")
    p_store_list.add_argument("--json", action="store_true", help="Emit JSON output")

    p_store_export = p_store_sub.add_parser("export", help="Export findings in JSON or TOON tabular format")
    p_store_export.add_argument("--run-id", required=True, help="Run ID to export")
    p_store_export.add_argument("--format", choices=["json", "toon", "minified", "markdown", "md"], default="toon", help="Export format")
    p_store_export.add_argument("--out", help="Output file path (default: stdout)")
    p_store_export.add_argument("--db", help="Path to SQLite database")

    p_store_prune = p_store_sub.add_parser("prune", help="Prune historical runs from blackboard store")
    p_store_prune.add_argument("--keep", type=int, default=20, help="Number of recent runs to keep (default: 20)")
    p_store_prune.add_argument("--db", help="Path to SQLite database")

    p_store_info = p_store_sub.add_parser("info", help="Show blackboard database status and counts")
    p_store_info.add_argument("--db", help="Path to SQLite database")
    p_store_info.add_argument("--json", action="store_true", help="Emit JSON output")

    # report (v2.0+)
    p_report = subparsers.add_parser("report", aliases=["summary", "synthesize"], help="Generate user-facing Markdown review summary report (v2.0+)")
    p_report.add_argument("--run-id", help="Filter by specific run_id (defaults to most recent run)")
    p_report.add_argument("--file", help="Path to JSON finding document or findings payload to synthesize directly")
    p_report.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Report output format (default: markdown)")
    p_report.add_argument("--out", help="Write report to output file (default: stdout)")
    p_report.add_argument("--db", help="Path to SQLite database (default: .ocagents/blackboard.db)")
    p_report.add_argument("--repo-url", help="Repository URL for clickable GitHub line anchor links")

    # run
    p_run = subparsers.add_parser("run", aliases=["simulate"], help="Run multi-agent pipeline simulation on an architectural task")
    p_run.add_argument("task", nargs="?", default="Architect multi-region payment DR failover with Aurora Global Database")
    p_run.add_argument("--task", dest="task_opt", help="Task prompt string")
    p_run.add_argument("--export-json", help="Export structured JSON execution trace")
    p_run.add_argument("--provider", default="simulated", choices=["simulated", "ollama", "gemini", "anthropic", "openai"], help="Execution engine provider")
    p_run.add_argument("--model", help="Model name override")

    # learn
    p_learn = subparsers.add_parser("learn", aliases=["postmortem", "ingest"], help="Ingest runtime edge case or incident postmortem into AGENTS.md")
    p_learn.add_argument("--incident", "--from-incident", dest="incident", help="Path to incident postmortem markdown file")
    p_learn.add_argument("--fact", help="Learned fact in 'Title: Description' format")
    p_learn.add_argument("--category", default="CI/CD & Autonomous Agent Governance", help="Target knowledge category")
    p_learn.add_argument("--dry-run", action="store_true", help="Preview ingestion without modifying AGENTS.md")

    # sandbox
    p_sandbox = subparsers.add_parser("sandbox", aliases=["test-k8s", "kind"], help="Run ephemeral KinD sandbox verification on manifests, Helm charts, or scenarios")
    p_sandbox.add_argument("--manifest", "--manifests", dest="manifest", help="Path to raw YAML manifest or directory of manifests")
    p_sandbox.add_argument("--helm", "--helm-chart", dest="helm", help="Path to Helm chart directory")
    p_sandbox.add_argument("--kustomize", dest="kustomize", help="Path to Kustomize overlay directory")
    p_sandbox.add_argument("--scenario", dest="scenario", help="Path to live failure/incident scenario for agent triage")
    p_sandbox.add_argument("--cluster-name", help="Custom KinD cluster name")
    p_sandbox.add_argument("--k8s-version", help="Kubernetes version image tag (e.g. v1.31.0, v1.30.2)")
    p_sandbox.add_argument("--ingress", action="store_true", help="Deploy ingress-nginx controller and map host ports 80/443")
    p_sandbox.add_argument("--keep-cluster", action="store_true", help="Retain KinD cluster after execution instead of auto-deleting")

    # info
    subparsers.add_parser("info", aliases=["status", "env"], help="Show environment, asset path, and CLI version")

    # update
    subparsers.add_parser("update", aliases=["upgrade"], help="Update the canonical agents catalog in ~/.open-cloud-agents")

    # help
    p_help = subparsers.add_parser("help", help="Show detailed command guides")
    p_help.add_argument("topic", nargs="?", help="Subcommand topic to explain")

    # version
    subparsers.add_parser("version", help="Show version details")

    try:
        parsed, unknown = parser.parse_known_args(normalized_args)
    except Exception:
        sys.exit(cmd_help(None))

    if parsed.version:
        sys.exit(cmd_version())
    if parsed.help or not parsed.subcommand:
        sys.exit(cmd_help(getattr(parsed, "subcommand", None) if parsed.help else None))

    asset_root = resolve_asset_root()

    if parsed.subcommand in ("list", "ls"):
        sys.exit(cmd_list(asset_root))
    elif parsed.subcommand == "sync":
        if getattr(parsed, "agent_opt", None):
            parsed.agent = parsed.agent_opt
        sys.exit(cmd_sync(parsed, asset_root))
    elif parsed.subcommand in ("validate", "check"):
        sys.exit(cmd_validate(asset_root))
    elif parsed.subcommand in ("preflight", "gate", "pre-flight"):
        sys.exit(cmd_preflight(parsed, asset_root))
    elif parsed.subcommand == "triage":
        sys.exit(cmd_triage(parsed, asset_root))
    elif parsed.subcommand in ("store", "findings-store"):
        sys.exit(cmd_store(parsed, asset_root))
    elif parsed.subcommand in ("report", "summary", "synthesize"):
        sys.exit(cmd_report(parsed, asset_root))
    elif parsed.subcommand in ("findings", "finding"):
        sys.exit(cmd_findings(parsed, asset_root))
    elif parsed.subcommand in ("run", "simulate"):
        if getattr(parsed, "task_opt", None):
            parsed.task = parsed.task_opt
        sys.exit(cmd_run(parsed, asset_root))
    elif parsed.subcommand in ("learn", "postmortem", "ingest"):
        sys.exit(cmd_learn(parsed, asset_root))
    elif parsed.subcommand in ("sandbox", "test-k8s", "kind"):
        sys.exit(cmd_sandbox(parsed, asset_root))
    elif parsed.subcommand in ("info", "status", "env"):
        sys.exit(cmd_info(asset_root))
    elif parsed.subcommand in ("update", "upgrade"):
        sys.exit(cmd_update(asset_root))
    elif parsed.subcommand == "help":
        sys.exit(cmd_help(getattr(parsed, "topic", None)))
    elif parsed.subcommand == "version":
        sys.exit(cmd_version())
    else:
        sys.exit(cmd_help(None))


if __name__ == "__main__":
    main()
