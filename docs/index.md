<p align="center">
  <img src="images/logo.svg" alt="Open Cloud Agents" width="160" />
</p>

# Open Cloud Agents

### Try cloud incident triage and infrastructure reviews in a local sandbox.

Open Cloud Agents is a local-first toolkit for AI-assisted cloud engineering. Start with the interactive demo: investigate a deliberately broken Kubernetes service, or review sample AWS, GCP, and Azure Terraform changes for security and operational risks.

**No production environment is needed for the demo.** It runs against local scenarios so you can explore the workflow before connecting an agent to your own tools or projects.

<p>
  <a href="https://github.com/open-cloud-agents/demo"><strong>Try the interactive demo →</strong></a>
  &nbsp; · &nbsp;
  <a href="https://github.com/open-cloud-agents/ocagents">Explore the CLI and framework</a>
</p>

---

## See it in action

The demo repository includes guided scenarios for:

- **Kubernetes incident triage:** investigate a sample billing-service outage in a local KinD cluster.
- **AWS Terraform review:** inspect a sample change for public ingress, TLS, and logging risks.
- **GCP Terraform review:** identify sample firewall, Cloud SQL, and storage exposure risks.
- **Azure Terraform review:** inspect sample network rules, public endpoints, and infrastructure changes.

### Run the interactive demo

Requirements and setup details are in the [demo repository](https://github.com/open-cloud-agents/demo). Its fast path uses Docker and local tools:

```bash
git clone https://github.com/open-cloud-agents/demo.git
cd demo
./run-demo.sh
```

Choose a scenario from the menu and follow its instructions. The demo uses intentionally broken sample workloads and infrastructure; it is a learning and evaluation sandbox, not a production deployment.

[Browse the demo scenarios →](https://github.com/open-cloud-agents/demo)

---

## What is Open Cloud Agents?

Open Cloud Agents provides a CLI, specialist agent instructions, reusable skills, and safety rules for cloud engineering workflows.

Instead of asking one general-purpose assistant to handle every task, the project organizes work by role:

- **Architecture:** explore design options and document trade-offs.
- **Security and DevSecOps:** review infrastructure changes and identify risks.
- **SRE:** investigate reliability and incident scenarios.
- **Release management:** reason about deployment and rollback plans.
- **FinOps:** analyze cost and resource-efficiency opportunities.

The project is at an early stage. Treat agent findings and suggested changes as recommendations to review—not as a substitute for engineering judgment, cloud-provider validation, or security review.

---

## Install the `ocagents` CLI

Choose an installation method documented for your platform:

### macOS and Linux

```bash
curl -fsSL https://open-cloud-agents.github.io/ocagents/install.sh | bash
```

### Windows PowerShell

```powershell
irm https://open-cloud-agents.github.io/ocagents/install.ps1 | iex
```

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

For the current install options and CLI usage, see the [Getting Started guide](./how-to-use-agents.md).

---

## Local-first and bring your own model

The CLI supports a simulation workflow and documented model-provider options. Model choice, credentials, network access, and data handling depend on the provider and configuration you use.

For provider setup and examples, see [How to Use Open Cloud Agents](./how-to-use-agents.md). Review your provider’s data-handling terms before sending it project or infrastructure context.

---

## Safety and scope

Cloud operations can affect availability, security, and cost. Use the project cautiously:

- Test with the provided local scenarios before using your own environment.
- Review commands, findings, and proposed changes before acting on them.
- Use least-privilege credentials when cloud access is needed.
- Do not provide secrets to a model or commit them to the repository.
- Do not run suggested infrastructure changes against production without independent review and approval.

The project includes safety rules and review-oriented workflows, but those are not a guarantee that every risk will be detected or every suggested action will be safe.

---

## Explore the project

- [Interactive demo and scenarios](https://github.com/open-cloud-agents/demo)
- [CLI and source code](https://github.com/open-cloud-agents/ocagents)
- [How to use agents](./how-to-use-agents.md)
- [Agent catalog](../agents/README.md)
- [Skills catalog](../skills/README.md)
- [Rules and guardrails](../rules/README.md)
- [Contributing](../CONTRIBUTING.md)

## Contributing

Contributions are welcome, including improvements to the demo scenarios, cloud review skills, agent instructions, tests, and documentation. See the [contribution guide](../CONTRIBUTING.md) to get started.

## License

Open Cloud Agents is licensed under the [Apache License 2.0](../LICENSE).
