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

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

__version__ = "1.3.1"

CANONICAL_REPO_URL = "https://github.com/open-cloud-agents/ocagents.git"
AVAILABLE_FORMATS = ["github", "claude", "cursor", "gemini", "raw"]

OCA_ASCII_BANNER = r""" ██████╗  ██████╗  █████╗ 
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
    return f"{c_cyan}{OCA_ASCII_BANNER}{c_reset}\n{c_bold}Open Cloud Agents (v{__version__}){c_reset}"


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


def parse_agent_frontmatter(file_path: Path) -> tuple[dict, str]:
    """Parse YAML frontmatter and body from agent markdown."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception:
        return {}, ""
    if not content.startswith("---"):
        return {}, content
    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, content
    fm_raw = parts[1]
    body = parts[2]
    meta = {}
    for line in fm_raw.strip().splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()
            if val.startswith("[") and val.endswith("]"):
                meta[key] = [item.strip() for item in val[1:-1].split(",") if item.strip()]
            else:
                meta[key] = val.strip('"\'')
    return meta, body


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
    c_reset = "\033[0m" if use_color else ""
    c_bold = "\033[1m" if use_color else ""

    print(f"\n☁️  {c_bold}Open Cloud Agents: 7-Agent Master Suite Registry{c_reset}")
    print("=" * 70)
    if not agents:
        log_fail(f"No agents found in {agents_dir}. Run 'ocagents update' to initialize assets.")
        return 1

    for slug, p in sorted(agents.items()):
        meta, _ = parse_agent_frontmatter(p)
        name = meta.get("name", slug)
        skills = meta.get("skills", [])
        tools = meta.get("tools", [])
        print(f"{c_bold_cyan}• {slug}{c_reset}: {c_bold_white}{name}{c_reset}")
        print(f"    {c_dim}↳ Tools:{c_reset} {c_green}[{', '.join(tools)}]{c_reset}")
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

    pipeline_script = asset_root / "scripts" / "agents" / "agent_pipeline.py"
    if pipeline_script.exists():
        res = subprocess.run([py_bin, str(pipeline_script), "--validate"])
        if res.returncode != 0:
            overall_rc = res.returncode
    else:
        log_fail(f"Pipeline validation script not found at: {pipeline_script}")
        overall_rc = 1

    ci_script = asset_root / "scripts" / "ci" / "validate_repo.py"
    if ci_script.exists():
        res_ci = subprocess.run([py_bin, str(ci_script)])
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
    """Updates or installs the canonical agents asset catalog in ~/.open-cloud-agents."""
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
    print("   • Founding Architect: Ibrahim Jimoh (https://www.linkedin.com/in/ijimoh)\n")
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
        else:
            normalized.append(arg)
        i += 1
    return normalized


def main():
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

    KNOWN_SUBCOMMANDS = ("list", "ls", "sync", "validate", "check", "run", "simulate", "learn", "postmortem", "ingest", "sandbox", "test-k8s", "kind", "info", "status", "env", "update", "upgrade")
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
        sys.exit(cmd_help(None))

    asset_root = resolve_asset_root()

    if parsed.subcommand in ("list", "ls"):
        sys.exit(cmd_list(asset_root))
    elif parsed.subcommand == "sync":
        if getattr(parsed, "agent_opt", None):
            parsed.agent = parsed.agent_opt
        sys.exit(cmd_sync(parsed, asset_root))
    elif parsed.subcommand in ("validate", "check"):
        sys.exit(cmd_validate(asset_root))
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
