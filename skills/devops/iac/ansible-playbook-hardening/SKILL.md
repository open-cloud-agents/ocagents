---
name: ansible-playbook-hardening
description: Scaffold, lint, and harden enterprise Ansible playbooks and roles with Ansible Vault encryption, strict idempotency, least-privilege execution, and dynamic multi-cloud inventory plugins.
---

# Ansible Playbook Hardening & Enterprise Automation

## Purpose & Scope

This skill provides production standards, safety guardrails, and validation workflows for authoring, linting, and hardening Ansible playbooks, roles, and collections. All automation engineered or reviewed under this skill must adhere to the 5 Enterprise Ansible Non-Negotiables: **idempotency, zero plaintext secrets, least-privilege privilege escalation (`become`), dynamic multi-cloud inventories, and automated linting**.

---

## 🏛️ Standard Ansible Enterprise Directory Layout

Every enterprise automation repository or collection must follow a modular layout:

```text
ansible-project/
├── ansible.cfg                # Strict configuration: roles_path, host_key_checking, vault_identity
├── inventory/
│   ├── production/
│   │   ├── aws_ec2.yml        # Dynamic AWS inventory plugin definition
│   │   ├── azure_rm.yml       # Dynamic Azure inventory plugin definition
│   │   └── group_vars/
│   │       ├── all/
│   │       │   ├── vars.yml   # Non-sensitive configuration variables
│   │       │   └── vault.yml  # Encrypted Ansible Vault credentials
│   │       └── webservers.yml
├── playbooks/
│   ├── site.yml               # Master orchestration entrypoint
│   └── patch-hosts.yml        # Surgical operational playbook
├── roles/
│   └── hardened_app/
│       ├── defaults/main.yml  # Lowest-priority default variables
│       ├── handlers/main.yml  # Service restart handlers (triggered via notify)
│       ├── tasks/main.yml     # Idempotent task declarations
│       ├── templates/         # Jinja2 configuration templates (.j2)
│       ├── vars/main.yml      # High-priority role variables
│       └── meta/main.yml      # Galaxy metadata and role dependencies
└── tests/
    └── molecule/default/      # Automated Molecule integration testing scenario
```

---

## 🚨 The 5 Enterprise Ansible Non-Negotiables

### 1. Strict Idempotency & State Enforcement
* **The Rule:** Re-running an Ansible playbook against an already-configured target must result in `changed=0 failed=0`.
* **The Trap:** Unbounded `ansible.builtin.command` or `ansible.builtin.shell` tasks execute on every run, breaking idempotency and triggering unnecessary service restarts.
* **Remediation:** Always prefer declarative modules (`ansible.builtin.copy`, `ansible.builtin.template`, `ansible.builtin.systemd`, `ansible.builtin.package`). When `command` or `shell` is unavoidable, you **must** supply `creates`, `removes`, or explicit `changed_when`:
  ```yaml
  - name: Generate self-signed certificate if missing
    ansible.builtin.command:
      cmd: openssl req -new -x509 -days 365 -nodes -out /etc/ssl/certs/app.crt -keyout /etc/ssl/private/app.key -subj "/CN=internal.corp"
    args:
      creates: /etc/ssl/certs/app.crt
  ```

### 2. Zero Plaintext Secrets (Ansible Vault & KMS)
* **The Rule:** Passwords, API tokens, private keys, and connection strings must never exist as plaintext in git.
* **Remediation:** Encrypt all sensitive variables with Ansible Vault (`ansible-vault encrypt_string` or vault files). Bind secrets dynamically at runtime from AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault via lookup plugins:
  ```yaml
  # Good: Lookup from cloud secret manager or encrypted vault variable
  db_password: "{{ lookup('amazon.aws.aws_secret', 'production/rds/db_password') }}"
  ```

### 3. Least Privilege & `become` Isolation
* **The Rule:** Never set `become: true` at the play level (`- hosts: all \n become: true`). Running an entire playbook as root increases the blast radius of script injection or unvetted tasks.
* **Remediation:** Keep `become: false` by default; apply `become: true` and specify unprivileged targets (`become_user: appuser`) only on tasks that require elevated capabilities.

### 4. Dynamic Multi-Cloud Inventories
* **The Rule:** Never use static `hosts.ini` files with hardcoded IP addresses for cloud infrastructure.
* **Remediation:** Use native cloud inventory plugins (`amazon.aws.aws_ec2`, `azure.azcollection.azure_rm`, `google.cloud.gcp_compute`) with keyed groups and tags:
  ```yaml
  # inventory/production/aws_ec2.yml
  plugin: amazon.aws.aws_ec2
  regions:
    - us-east-1
  filters:
    tag:Environment: production
    instance-state-name: running
  keyed_groups:
    - key: tags.Role
      prefix: role
  ```

### 5. Automated Static Linting (`ansible-lint`)
* **The Rule:** All playbooks and roles must pass `ansible-lint` with zero violations before merging.
* **Checks Enforced:** Banning deprecated syntax, verifying Jinja2 quoting rules (`"{{ my_var }}"`), and enforcing FQCN (Fully Qualified Collection Names) such as `ansible.builtin.template`.

---

## 🛠️ Step-by-Step Hardening Workflow

- [ ] 1. **Check Syntax & Format:**
  ```bash
  ansible-playbook playbooks/site.yml --syntax-check
  ```
- [ ] 2. **Run Security & Hygiene Audit:**
  ```bash
  ./scripts/audit_playbook_hygiene.sh playbooks/
  ```
- [ ] 3. **Execute Static Analysis:**
  ```bash
  ansible-lint playbooks/site.yml
  ```
- [ ] 4. **Dry-Run Check Mode (Idempotency Preview):**
  ```bash
  ansible-playbook playbooks/site.yml --check --diff
  ```

---

## ⚠️ Known Edge Cases & Production Traps

* **Jinja2 Quoting Syntax Error:** Writing `key: {{ value }}` triggers YAML parsing errors. Always wrap Jinja2 expressions in quotes: `key: "{{ value }}"`.
* **Handlers Suppressed by Task Failures:** By default, if a play fails, notified handlers never run. In zero-downtime maintenance plays, configure `force_handlers: true` or execute `ansible.builtin.meta: flush_handlers` before critical milestones.
* **Register Variable Overwrites in Loops:** Registering output in a loop creates a list in `my_var.results`, not a top-level dictionary. Inspect items via `{{ my_var.results | map(attribute='stdout') | list }}`.

---

## 📚 References & Scripts

* [ansible-vault-and-secret-hygiene.md](references/ansible-vault-and-secret-hygiene.md): Vault encryption patterns and KMS key providers.
* [ansible-idempotency-and-linting.md](references/ansible-idempotency-and-linting.md): Idempotency enforcement, FQCN standards, and Molecule testing.
* [audit_playbook_hygiene.sh](scripts/audit_playbook_hygiene.sh): Automated playbook static scanner.

