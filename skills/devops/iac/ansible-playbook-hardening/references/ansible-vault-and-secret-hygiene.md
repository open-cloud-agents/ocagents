# Ansible Vault & Enterprise Secret Hygiene

This reference details the security standards for encrypting, managing, and retrieving secrets in Ansible automation.

---

## 🔒 1. Ansible Vault Standards

### Encrypting Variables with Vault IDs

Always label Vault identities (`--vault-id`) to support multi-environment or multi-team segregation:

```bash
# Encrypt an individual secret variable inline:
ansible-vault encrypt_string --vault-id prod@prompt 'SuperSecretP@ssw0rd' --name 'vault_db_password'

# Encrypt an entire group_vars file:
ansible-vault encrypt --vault-id prod@/path/to/keyfile inventory/production/group_vars/all/vault.yml
```

### Decoupling Secret Keys from Workstations

Never store static vault password files on developer disks. Use dynamic credential helper scripts:

```ini
# ansible.cfg
[defaults]
vault_identity_list = prod@scripts/vault_keyring_client.sh, dev@~/.vault_dev
```

---

## ☁️ 2. Dynamic Secret Lookups (Cloud Secret Managers)

Rather than storing encrypted blobs in git, prefer dynamic runtime lookups from cloud KMS / Secret Managers:

### AWS Secrets Manager Lookup
```yaml
- name: Fetch database credentials dynamically
  ansible.builtin.set_fact:
    db_credentials: "{{ lookup('amazon.aws.aws_secret', 'production/aurora/credentials') | from_json }}"
  no_log: true
```

### HashiCorp Vault Lookup
```yaml
- name: Read secret from HashiCorp Vault KV v2
  ansible.builtin.set_fact:
    tls_private_key: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/data/production/tls:private_key') }}"
  no_log: true
```

> [!IMPORTANT]
> Always set `no_log: true` on any task that registers, inspects, or outputs sensitive variables to prevent plaintext leaking into Ansible execution logs or CI console outputs.

