<p align="center">
  <img src="images/logo.svg" alt="Open Cloud Agents" width="160" />
</p>

# Open Cloud Agents

### Explore cloud incident triage and infrastructure reviews in a local demo sandbox.

Open Cloud Agents is a local-first toolkit for AI-assisted cloud engineering. Start with the interactive demo: investigate a sample Kubernetes outage or review example AWS, GCP, and Azure Terraform changes for security and operational risks.

**New here? Start with the demo.**

<p>
  <a href="https://github.com/open-cloud-agents/demo"><strong>Try the interactive demo →</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/open-cloud-agents/ocagents">Explore the CLI and framework</a>
</p>

---

## Try the demo first

The [demo repository](https://github.com/open-cloud-agents/demo) contains guided scenarios for:

- **Kubernetes incident triage:** investigate a sample billing-service outage using a local KinD cluster.
- **AWS Terraform review:** examine sample infrastructure changes for security and operational risks.
- **GCP Terraform review:** inspect example network, Cloud SQL, and storage configuration.
- **Azure Terraform review:** inspect example network and infrastructure changes.
- **Multi-cloud review:** run the available IaC review scenarios.

The demo’s fast track uses Docker and local tools; follow the scenario instructions for specific prerequisites.

```bash
git clone https://github.com/open-cloud-agents/demo.git
cd demo
./run-demo.sh
```

Choose a scenario from the interactive menu and follow its walkthrough. These are sample scenarios for learning and evaluation—not production environments. Review any generated recommendations before applying changes.

**[Browse the demo scenarios and setup instructions →](https://github.com/open-cloud-agents/demo)**

---

## What is Open Cloud Agents?

Open Cloud Agents provides a CLI, specialist agent instructions, reusable skills, and safety rules for cloud engineering workflows.

Instead of asking one general-purpose assistant to handle every task, the project organizes work by role:

- **Architecture:** explore design options and document trade-offs.
- **Security and DevSecOps:** review infrastructure changes and identify risks.
- **SRE:** investigate reliability and incident scenarios.
- **Release management:** reason about deployment and rollback plans.
- **FinOps:** analyze cost and resource-efficiency opportunities.

The project is early-stage. Treat agent findings and suggestions as recommendations to review—not as a substitute for engineering judgment, cloud-provider validation, or security review.

---

## Install the `ocagents` CLI

Install the CLI if you want to explore workflows beyond the demo.

### macOS and Linux

```bash
curl -fsSL https://open-cloud-agents.github.io/ocagents/install.sh | bash
```
> *Security note:* Inspect the installer script at [`install.sh`](https://github.com/open-cloud-agents/ocagents/blob/main/install.sh) before running.

### Windows PowerShell

```powershell
irm https://open-cloud-agents.github.io/ocagents/install.ps1 | iex
```
> *Security note:* Inspect the installer script at [`install.ps1`](https://github.com/open-cloud-agents/ocagents/blob/main/install.ps1) before running.

### Homebrew

```bash
brew tap open-cloud-agents/tap
brew install ocagents
```

### Python with pipx

```bash
pipx install git+https://github.com/open-cloud-agents/ocagents.git
```

Verify the installation:

```bash
ocagents --help
```

See the [CLI guide](./how-to-use-agents.md) for current installation options and usage.

---

## Choose a model—or try simulation

The CLI documents support for local models, hosted model providers, and a simulation workflow. The exact setup depends on the provider and configuration.

For example, the provider guide shows how to run with Ollama:

```bash
ocagents run \
  --provider ollama \
  --model llama3 \
  --task "Review this Kubernetes configuration for reliability risks"
```

You can also try the documented simulation workflow without configuring a model provider:

```bash
ocagents run --task "Review a sample cloud architecture"
```

See [How to Use Open Cloud Agents](./how-to-use-agents.md) for provider setup and current examples.

> **Data handling:** With a locally hosted model, model inference can run on your machine; network access may still be used by other tools or integrations. Hosted model providers may receive prompts and context sent by the CLI. Review your provider’s data-handling terms, and do not put cloud credentials or sensitive infrastructure details in prompts.

---

## Safety and scope

Cloud operations can affect availability, security, and cost. Use the project cautiously:

- The demo is designed to run locally and does not require production credentials. Review its scripts and prerequisites before running it.
- Test with the provided sample scenarios before using your own environment.
- Review commands, findings, and proposed changes before acting on them.
- Use least-privilege credentials when cloud access is needed.
- Keep secrets out of prompts, logs, and version control.
- Require independent review and approval before applying changes to production.

The project includes safety rules and review-oriented workflows, but these do not guarantee that every risk will be detected or every recommendation will be safe.

---

## Explore the project

- [Interactive demo and scenarios](https://github.com/open-cloud-agents/demo)
- [CLI and source code](https://github.com/open-cloud-agents/ocagents)
- [How to use agents](./how-to-use-agents.md)
- [Agent catalog](../agents/README.md)
- [Skills catalog](../skills/README.md)
- [Rules and guardrails](../rules/README.md)
- [Contributing](../CONTRIBUTING.md)
