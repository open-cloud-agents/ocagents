# Contributing to Open Cloud Agents

Thank you for your interest in contributing to **Open Cloud Agents**! We are building an open, enterprise-grade multi-agent cloud architecture mapped across the AWS, Azure, and Google Cloud Well-Architected Frameworks.

By contributing, you help make cloud architecture, security, GitOps, SRE, and FinOps more reliable and autonomous for engineering teams worldwide.

---

## How You Can Contribute

We welcome contributions in several key areas:

### 1. New Agent Personas
Have an idea for a specialized agent (e.g., `mlops-engineer`, `database-reliability-architect`, `identity-zero-trust-specialist`)?
- Follow the structure used in `agents/7-agent-master-suite/`.
- Ensure each agent includes:
  - Strict scope and mandate
  - Explicit non-goals (what the agent does *not* own)
  - Clear input/output handoffs with upstream and downstream agents
  - Negative trade-off accounting and safety guardrails

### 2. Improving Agent Prompts & Guardrails
- Refining system instructions to eliminate hallucinations.
- Hardening destructive action checks (e.g., state-loss prevention in Terraform/OpenTofu, zero-downtime database migrations).
- Updating tool definitions to support new MCP servers and cloud provider APIs.

### 3. Benchmarks & Real-World Evaluation Cases
- Share prompt evaluations, scenario tests, and test suites that evaluate agent performance across real multi-cloud topologies.

### 4. Bug Reports & Architectural RFCs
- If an agent suggests an outdated pattern, non-optimal cloud tiering, or fails a security standard, open an Issue with context and proposed remediations.

---

## Contribution Process

1. **Fork the Repository** and create your branch from `main`:
   ```bash
   git checkout -b feat/my-new-agent
   ```
   > **Windows:** some catalog file paths are longer than Windows' default 260-character limit. Run `git config --global core.longpaths true` once before cloning, otherwise Git fails with `Filename too long`.
2. **Make Your Changes** following our engineering standards (see [`docs/engineering-standards.md`](./docs/engineering-standards.md)).
3. **Run the Local Validation Suite & CI (`act`):**
   Before pushing, verify all skill specs, permissions, and markdown links pass:
   ```bash
   # Option A: Fast lightweight check (Python):
   python3 scripts/ci/validate_repo.py
   python3 scripts/agents/agent_pipeline.py --validate

   # Option B: Run the full GitHub Actions CI suite locally in Docker with act:
   act --container-architecture linux/amd64
   ```
4. **Guardrail Checklist:**
   - [ ] No hardcoded secrets, keys, or credentials (verified by Gitleaks in CI).
   - [ ] All shell scripts have executable bits (`chmod +x scripts/*.sh`).
   - [ ] Skill specs have valid YAML frontmatter (`name:`, `description:`).
   - [ ] Internal markdown links resolve properly without broken relative paths.
   - [ ] Follows conventional commits (`feat:`, `fix:`, `docs:`, `chore:`).
5. **Submit a Pull Request** with a concise description of your changes, the rationale, and any sample outputs or tests.
6. **Sign Off & Join the Roster:** Fill out the Contributor Sign-Off section in your PR and add your entry to [**`CONTRIBUTORS.md`**](./CONTRIBUTORS.md).

---

## ✍️ Contributor Sign-Off & Recognition

We believe every contributor deserves public recognition for their work. When you contribute to Open Cloud Agents, you can sign off your contribution and join our [**Contributors Hall of Fame (CONTRIBUTORS.md)**](./CONTRIBUTORS.md).

### 1. Developer Certificate of Origin (DCO) Sign-Off
We enforce standard DCO sign-offs on all commits. You can automatically sign off commits using the `-s` flag:
```bash
git commit -s -m "feat(skills): add automated canary rollback verification script"
```
This appends a verifiable sign-off line:
```text
Signed-off-by: Your Name <your.email@example.com>
```

### 2. Standard Email Practice: GitHub Privacy Alias (Recommended)
Following standard open-source industry practice and to protect community members against automated web scrapers and spambots, we recommend signing off with your **GitHub Privacy No-Reply Email**:
```text
<username>@users.noreply.github.com
```
You can find your private GitHub address under [GitHub Settings > Emails > Keep my email addresses private](https://github.com/settings/emails).

For direct professional networking, we encourage contributors to link their **LinkedIn Profile** or **Google Developer Profile** instead of exposing personal mailboxes. Standard public emails are also accepted if preferred.

### 3. Professional Profiles (LinkedIn & Google Developer)
To showcase your cloud and AI engineering credentials, you are encouraged to link:
* **LinkedIn Profile:** e.g., `https://www.linkedin.com/in/<username>`
* **Google Developer Profile:** e.g., `https://g.dev/<username>`

### 4. Adding Yourself to `CONTRIBUTORS.md`
With your pull request, feel free to add your name, focus area, and profile badges directly to [**`CONTRIBUTORS.md`**](./CONTRIBUTORS.md)!

---

## Community & Conduct

We are committed to providing a friendly, safe, and welcoming environment for all contributors. Please treat others with respect and constructive professionalism.

