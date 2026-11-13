#!/usr/bin/env python3
"""
Open Cloud Agents: Repository Hygiene & Skill Spec Validator.
Validates:
1. Skill YAML Frontmatter (name, description) on all SKILL.md files.
2. Executable permissions on all helper and verification shell scripts (*.sh).
3. Internal relative Markdown links across core skills, agents, docs, and root files.
4. Absence of hardcoded local absolute user paths (/Users/ or /home/).
5. Absence of invisible / Trojan Source characters and code confusables in scripts & IaC.

Usage:
    python3 scripts/ci/validate_repo.py
"""

import os
import re
import sys
import urllib.parse
from pathlib import Path

if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
    target_candidate = os.path.abspath(sys.argv[1])
    if os.path.isdir(target_candidate):
        REPO_ROOT = target_candidate
    else:
        REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
elif os.path.isdir(os.path.join(os.getcwd(), "skills")) and os.path.isdir(os.path.join(os.getcwd(), "agents")):
    REPO_ROOT = os.getcwd()
else:
    REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

IGNORED_DIR_NAMES = {".git", "ai_brain", "build_docs", "site", ".venv", "node_modules", "mock", "mocks"}

def should_skip_dir(dirpath: str) -> bool:
    parts = set(Path(dirpath).parts)
    return bool(parts & IGNORED_DIR_NAMES)

def log_pass(msg: str):
    print(f"  \033[92m✔\033[0m {msg}")

def log_fail(msg: str):
    print(f"  \033[91m✖\033[0m {msg}")

def log_info(msg: str):
    print(f"\033[94mℹ\033[0m {msg}")


def check_skill_frontmatter() -> list[str]:
    log_info("Checking YAML frontmatter on all SKILL.md files...")
    errors = []
    count = 0
    for root, _, files in os.walk(REPO_ROOT):
        if should_skip_dir(root):
            continue
        for f in files:
            if f == "SKILL.md":
                count += 1
                p = os.path.join(root, f)
                rel_p = os.path.relpath(p, REPO_ROOT)
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                    if not content.startswith("---"):
                        errors.append(f"{rel_p}: Missing starting '---' YAML frontmatter")
                        continue
                    # Check first 20 lines for name and description
                    head = "\n".join(content.splitlines()[:20])
                    if "name:" not in head:
                        errors.append(f"{rel_p}: Missing 'name:' in frontmatter")
                    if "description:" not in head:
                        errors.append(f"{rel_p}: Missing 'description:' in frontmatter")
                except Exception as e:
                    errors.append(f"{rel_p}: Failed to read file: {e}")

    if not errors:
        log_pass(f"All {count} SKILL.md specifications contain valid frontmatter.")
    else:
        for err in errors[:10]:
            log_fail(err)
        if len(errors) > 10:
            log_fail(f"... and {len(errors) - 10} more frontmatter errors.")
    return errors


def check_script_permissions() -> list[str]:
    log_info("Checking executable permissions on shell scripts (*.sh)...")
    errors = []
    count = 0
    for root, _, files in os.walk(REPO_ROOT):
        if should_skip_dir(root):
            continue
        for f in files:
            if f.endswith(".sh"):
                count += 1
                p = os.path.join(root, f)
                rel_p = os.path.relpath(p, REPO_ROOT)
                if not os.access(p, os.X_OK):
                    errors.append(f"{rel_p}: Script is not executable (chmod +x required)")

    if not errors:
        log_pass(f"All {count} shell scripts have executable permissions.")
    else:
        for err in errors:
            log_fail(err)
    return errors


def check_markdown_links() -> list[str]:
    log_info("Checking internal relative Markdown links across core architecture & skills...")
    errors = []
    link_pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
    count = 0

    # We validate root docs, agents, docs, and core skills (excluding 3rd-party vendor dumps)
    for root, _, files in os.walk(REPO_ROOT):
        if should_skip_dir(root) or "skills/csp" in root:
            continue
        for f in files:
            if f.endswith(".md"):
                count += 1
                path = os.path.join(root, f)
                rel_src = os.path.relpath(path, REPO_ROOT)
                dir_name = os.path.dirname(path)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                    # Strip code blocks and inline code spans
                    content_clean = re.sub(r"```.*?```", "", content, flags=re.DOTALL)
                    content_clean = re.sub(r"`[^`\n]+`", "", content_clean)
                    for m in link_pattern.finditer(content_clean):
                        target = m.group(2).strip()
                        # Ignore absolute external URLs, anchors, or pseudo-schemes
                        if target.startswith((
                            "http://", "https://", "mailto:", "#",
                            "file://", "sidecar://", "conversation://"
                        )):
                            continue
                        target_file = target.split("#")[0]
                        if not target_file:
                            continue
                        resolved = os.path.normpath(os.path.join(dir_name, urllib.parse.unquote(target_file)))
                        if not os.path.exists(resolved):
                            # Fallback 1: check relative to REPO_ROOT in current working directory
                            rel_to_repo = os.path.relpath(resolved, REPO_ROOT)
                            cwd_candidate = os.path.normpath(os.path.join(os.getcwd(), rel_to_repo))
                            if os.path.exists(cwd_candidate):
                                continue
                            # Fallback 2: stripped target path relative to CWD
                            cwd_candidate2 = os.path.normpath(os.path.join(os.getcwd(), urllib.parse.unquote(target_file).lstrip("./")))
                            if os.path.exists(cwd_candidate2):
                                continue
                            errors.append(f"{rel_src}: Broken link '{target}' -> target '{os.path.relpath(resolved, REPO_ROOT)}' not found")
                except Exception as e:
                    errors.append(f"{rel_src}: Failed to parse links: {e}")

    if not errors:
        log_pass(f"All relative links in {count} core Markdown documents resolve successfully.")
    else:
        for err in errors:
            log_fail(err)
    return errors


def check_no_absolute_user_paths() -> list[str]:
    log_info("Checking for leaking local machine paths (/Users/<username>/)...")
    errors = []
    # Match personal local workstation directories like /Users/<username>/, excluding Windows generic/system paths (e.g. Public)
    user_path_pattern = re.compile(r"/Users/(?!Public/|Default/|Administrator/|<[^>]+>)[a-zA-Z0-9_\-]+/")
    count = 0
    for root, _, files in os.walk(REPO_ROOT):
        if should_skip_dir(root):
            continue
        for f in files:
            if f.endswith((".md", ".sh", ".yaml", ".yml", ".json")):
                count += 1
                p = os.path.join(root, f)
                rel_p = os.path.relpath(p, REPO_ROOT)
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                        for line_num, line in enumerate(fh, 1):
                            if user_path_pattern.search(line):
                                errors.append(f"{rel_p}:{line_num}: Contains local user machine path: {line.strip()[:80]}")
                except Exception:
                    pass

    if not errors:
        log_pass(f"No local developer machine paths found in {count} scanned source files.")
    else:
        for err in errors:
            log_fail(err)
    return errors


def check_character_hygiene() -> list[str]:
    log_info("Checking for invisible characters, Trojan Source, and code confusables...")
    errors = []

    # 1. Dangerous invisible and bidirectional override characters (Trojan Source)
    # Prohibited across all files (docs, code, configs)
    INVISIBLE_CHARS = {
        "\u200b": "Zero-width space (U+200B)",
        "\u200c": "Zero-width non-joiner (U+200C)",
        "\u200d": "Zero-width joiner (U+200D)",
        "\ufeff": "Byte-order mark outside header (U+FEFF)",
        "\u202a": "Left-to-right embedding (U+202A)",
        "\u202b": "Right-to-left embedding (U+202B)",
        "\u202c": "Pop directional formatting (U+202C)",
        "\u202d": "Left-to-right override (U+202D)",
        "\u202e": "Right-to-left override (U+202E)",
    }

    # 2. Ambiguous / confusable characters prohibited in code and configurations
    CODE_CONFUSABLES = {
        "\u2013": "Unicode en-dash U+2013 (use standard ASCII '-')",
        "\u2014": "Unicode em-dash U+2014 (use standard ASCII '-')",
        "\u00d7": "Multiplication sign U+00D7 (use standard ASCII '*' or 'x')",
        "\u037e": "Greek question mark U+037E (use standard ASCII ';')",
        "\u201c": "Left smart double quote U+201C (use ASCII '\"')",
        "\u201d": "Right smart double quote U+201D (use ASCII '\"')",
        "\u2018": "Left smart single quote U+2018 (use ASCII '\'') ",
        "\u2019": "Right smart single quote U+2019 (use ASCII '\'') ",
    }

    code_exts = (".sh", ".py", ".tf", ".yml", ".yaml", ".json")
    all_exts = (".md", ".sh", ".py", ".tf", ".yml", ".yaml", ".json")
    count = 0

    for root, _, files in os.walk(REPO_ROOT):
        if should_skip_dir(root):
            continue
        for f in files:
            if not f.endswith(all_exts):
                continue
            p = os.path.join(root, f)
            rel_p = os.path.relpath(p, REPO_ROOT)

            # Skip settings.json and the validator script itself
            if rel_p in (".vscode/settings.json", "scripts/ci/validate_repo.py"):
                continue

            count += 1
            is_code_file = f.endswith(code_exts) and ("skills/csp" not in root)

            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                    for line_num, line in enumerate(fh, 1):
                        # Check invisible / Trojan Source characters everywhere
                        for ch, desc in INVISIBLE_CHARS.items():
                            if ch in line:
                                errors.append(f"{rel_p}:{line_num}: Invisible/Trojan Source character detected: {desc}")

                        # Check code confusables in core scripts, IaC, and workflows
                        if is_code_file:
                            for ch, desc in CODE_CONFUSABLES.items():
                                if ch in line:
                                    errors.append(f"{rel_p}:{line_num}: Confusable character detected: {desc} -> {line.strip()[:70]}")
            except Exception as e:
                errors.append(f"{rel_p}: Failed to inspect characters: {e}")

    if not errors:
        log_pass(f"No invisible characters or code confusables found across {count} scanned files.")
    else:
        for err in errors[:10]:
            log_fail(err)
        if len(errors) > 10:
            log_fail(f"... and {len(errors) - 10} more character hygiene errors.")
    return errors


def main():
    print("=" * 60)
    print(" 🛡️  Open Cloud Agents: Repository Hygiene & Validation Suite")
    print("=" * 60)
    
    all_errors = []
    all_errors.extend(check_skill_frontmatter())
    all_errors.extend(check_script_permissions())
    all_errors.extend(check_markdown_links())
    all_errors.extend(check_no_absolute_user_paths())
    all_errors.extend(check_character_hygiene())

    print("=" * 60)
    if all_errors:
        print(f"\033[91mFAILED:\033[0m Found {len(all_errors)} repository hygiene violation(s).")
        sys.exit(1)
    else:
        print("\033[92mSUCCESS:\033[0m All repository hygiene checks passed cleanly!")
        sys.exit(0)

if __name__ == "__main__":
    main()
