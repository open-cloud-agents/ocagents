# Ansible Idempotency, FQCN & Molecule Testing Standards

This reference covers the engineering practices required to guarantee that Ansible automation is idempotent, testable, and compliant with enterprise linting profiles.

---

## ⚡ 1. Idempotency Invariants

An idempotent task leaves the system in the identical target state on repeat runs without making extraneous modifications.

### Good vs Bad Patterns

#### Bad: Non-Idempotent Shell Command
```yaml
# ❌ BAD: Runs every time, reports 'changed', triggers unnecessary restarts
- name: Extract archive
  ansible.builtin.shell: tar -xzf /tmp/app.tar.gz -C /opt/app/
```

#### Good: Declarative Built-in Module
```yaml
# ✔ GOOD: Only extracts if target directory lacks contents or checksum mismatch
- name: Extract archive idempotently
  ansible.builtin.unarchive:
    src: /tmp/app.tar.gz
    dest: /opt/app/
    remote_src: true
    creates: /opt/app/bin/start.sh
```

#### Good: Guarded Command with `changed_when`
```yaml
# ✔ GOOD: Custom shell invocation with explicit idempotency check
- name: Rebuild application cache
  ansible.builtin.command: /opt/app/bin/rebuild-cache.sh
  register: cache_result
  changed_when: "'Cache updated' in cache_result.stdout"
  failed_when: cache_result.rc != 0
```

---

## 📦 2. Fully Qualified Collection Names (FQCN)

Always use FQCNs to ensure predictable resolution across environments:

* `ansible.builtin.copy` (instead of `copy`)
* `ansible.builtin.template` (instead of `template`)
* `ansible.builtin.service` / `ansible.builtin.systemd` (instead of `service`)
* `ansible.posix.firewalld`
* `amazon.aws.ec2_instance`

---

## 🧪 3. Automated Testing with Molecule

Molecule tests roles across temporary containerized environments:

```bash
# Initialize Molecule scenario with podman/docker driver:
molecule init scenario --driver-name podman

# Run full test sequence (lint, create, converge, idempotence, verify, destroy):
molecule test
```

A passing `molecule idempotence` step verifies that the second play run produces zero changes (`changed=0`).
