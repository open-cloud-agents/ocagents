"""
Open Cloud Agents: YAML Frontmatter Parser.

Provides zero-dependency parsing of YAML frontmatter headers from Markdown
specifications (agents, skills, rules) into typed Python dictionaries and
content bodies.
"""

from pathlib import Path


def parse_scalar(val: str):
    """Parse scalar or inline list from YAML frontmatter into a typed Python object."""
    val = val.strip()
    if val.startswith("[") and val.endswith("]"):
        return [item.strip().strip("'\"") for item in val[1:-1].split(",") if item.strip()]

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


def parse_frontmatter(content: str) -> tuple[dict, str]:
    """Extract YAML frontmatter and body, supporting flat keys, inline lists, and nested mappings."""
    if not content.startswith("---"):
        return {}, content
    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, content

    fm_raw = parts[1]
    body = parts[2]
    meta: dict = {}
    current_parent: str | None = None

    for raw_line in fm_raw.strip().splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if ":" not in stripped:
            continue

        if indent > 0 and current_parent and isinstance(meta.get(current_parent), dict):
            sub_k, sub_v = stripped.split(":", 1)
            meta[current_parent][sub_k.strip()] = parse_scalar(sub_v)
        else:
            k, v = stripped.split(":", 1)
            k = k.strip()
            v = v.strip()
            if not v:
                current_parent = k
                meta[k] = {}
            else:
                current_parent = None
                meta[k] = parse_scalar(v)

    return meta, body


def parse_agent_frontmatter(file_path: Path) -> tuple[dict, str]:
    """Parse YAML frontmatter and body directly from a specification file."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception:
        return {}, ""
    return parse_frontmatter(content)
