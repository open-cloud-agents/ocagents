#!/usr/bin/env python3
# ==============================================================================
# Open Cloud Agents: Documentation Preparation Script for MkDocs / GitHub Pages
#
# Stages all in-repo Markdown documents (Single Source of Truth) into a unified
# build_docs/ directory for MkDocs static site generation.
# ==============================================================================

import os
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_DOCS = REPO_ROOT / "build_docs"


def log(msg: str):
    print(f"ℹ [Docs Builder] {msg}")


def prepare_docs():
    log(f"Staging docs into: {BUILD_DOCS}")

    if BUILD_DOCS.exists():
        shutil.rmtree(BUILD_DOCS)
    BUILD_DOCS.mkdir(parents=True, exist_ok=True)

    # 1. Homepage: Copy dedicated docs/index.md (or fallback to README.md) as index.md
    docs_index_src = REPO_ROOT / "docs" / "index.md"
    readme_src = REPO_ROOT / "README.md"
    if docs_index_src.exists():
        content = docs_index_src.read_text(encoding="utf-8")
        # Adjust relative links for the root of build_docs
        content_transformed = (
            content.replace("../agents/", "agents/")
            .replace("../rules/", "rules/")
            .replace("../skills/", "skills/")
            .replace("../AGENTS.md", "AGENTS.md")
            .replace("../CONTRIBUTING.md", "CONTRIBUTING.md")
            .replace("../LICENSE", "LICENSE")
            .replace("./package-distribution-and-updates.md", "docs/package-distribution-and-updates.md")
            .replace("./architecture-mvp-spec.md", "docs/architecture-mvp-spec.md")
            .replace("./how-to-use-agents.md", "docs/how-to-use-agents.md")
            .replace("./engineering-standards.md", "docs/engineering-standards.md")
            .replace("./adr-002-blackboard-findings-and-token-budgets.md", "docs/adr-002-blackboard-findings-and-token-budgets.md")
        )
        (BUILD_DOCS / "index.md").write_text(content_transformed, encoding="utf-8")
        log("Staged dedicated docs/index.md -> index.md (Docs Landing Page)")
    elif readme_src.exists():
        shutil.copy2(readme_src, BUILD_DOCS / "index.md")
        log("Staged README.md -> index.md (Homepage Fallback)")

    # 2. Core Root Documents
    core_files = [
        "AGENTS.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "CONTRIBUTORS.md",
        "LICENSE",
        "install.sh",
        "install.ps1",
    ]
    for filename in core_files:
        src = REPO_ROOT / filename
        if src.exists():
            shutil.copy2(src, BUILD_DOCS / filename)
            log(f"Staged {filename}")

    # 3. Core Architecture Trees
    core_trees = ["agents", "rules", "skills"]
    for tree in core_trees:
        src = REPO_ROOT / tree
        dest = BUILD_DOCS / tree
        if src.exists():
            shutil.copytree(src, dest, ignore=shutil.ignore_patterns(".git*", "__pycache__", "*.pyc"))
            log(f"Staged {tree}/ directory")

    # 4. Existing docs/ directory content
    docs_dir = REPO_ROOT / "docs"
    if docs_dir.exists():
        dest_docs = BUILD_DOCS / "docs"
        shutil.copytree(docs_dir, dest_docs, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git*", "__pycache__", "*.pyc"))
        log("Staged docs/ directory into build_docs/docs/")
        
        # Also stage docs/images to build_docs/images for root index.md references
        images_dir = docs_dir / "images"
        if images_dir.exists():
            shutil.copytree(images_dir, BUILD_DOCS / "images", dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git*", "__pycache__", "*.pyc"))
            log("Staged docs/images/ directory into build_docs/images/")

        # Transform image asset paths for nested documentation pages in MkDocs directory URLs
        # (e.g. site/docs/how-to-use-agents/index.html requires ../images/ to reach site/docs/images/)
        for md_file in dest_docs.glob("*.md"):
            md_content = md_file.read_text(encoding="utf-8")
            transformed_md = (
                md_content.replace('src="./images/', 'src="../images/')
                .replace('src="images/', 'src="../images/')
                .replace('src="./docs/images/', 'src="../images/')
            )
            if transformed_md != md_content:
                md_file.write_text(transformed_md, encoding="utf-8")
                log(f"Adjusted image asset paths in staged docs/{md_file.name}")

        # Also stage docs/images into nested page subdirectories to guarantee resolution in all contexts
        for subdoc in ["how-to-use-agents", "architecture-mvp-spec", "engineering-standards", "token-optimization-architecture", "package-distribution-and-updates"]:
            sub_img_dir = dest_docs / subdoc / "images"
            if images_dir.exists():
                shutil.copytree(images_dir, sub_img_dir, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git*", "__pycache__", "*.pyc"))

    log("Documentation preparation completed successfully!")


if __name__ == "__main__":
    prepare_docs()

