# Infrastructure as Code (IaC) Skills

Curated agent skills for declarative cloud infrastructure authoring, static analysis, state protection, and drift remediation.

## Target Skill Areas
- **`terraform-infrastructure-planner`**: Centralized, machine-readable pre-code infrastructure planning in `.terraform-planning-files/INFRA.{provider}.{goal}.md` aligned to multi-cloud (AWS, Azure, GCP) and Docker Well-Architected Framework pillars.
- **`aws-terraform-implementation`**: Production HCL implementation adhering to module-first patterns, IAM least-privilege, and S3 secure defaults in `infrastructure/`.
- **`azure-terraform-implementation`**: Production Azure Terraform authoring adhering to verified `Azure/` modules, least-privilege Entra ID RBAC, Key Vault CMK encryption, and Storage Account secure defaults.
- **`gcp-terraform-implementation`**: Production GCP Terraform authoring adhering to verified `terraform-google-modules/`, least-privilege Cloud IAM, Cloud KMS CMEK encryption, and GCS secure defaults.
- **`docker-terraform-implementation`**: Hardened container orchestration using `kreuzwerker/docker` enforcing non-root execution, read-only root filesystems, dropped capabilities, and custom bridge network isolation.
- **`terraform-opentofu-modules`**: Reusable, parameterized module design with strict variable validation.
- **`ansible-playbook-hardening`**: Enterprise Ansible playbook hardening with Ansible Vault encryption, strict idempotency, least-privilege `become` isolation, and dynamic cloud inventories.
- **`iac-state-protection`**: Preventing unintentional resource replacements (`forces replacement` traps) and state lock deadlocks.

