# Secure Platform: A DevSecOps and Detection Engineering Home Lab

A home lab I'm building in public to show how I secure infrastructure and
software delivery end to end: hardened Linux hosts managed as code, a CI/CD
pipeline with security gates, Kubernetes with admission control, and
detection engineering mapped to MITRE ATT&CK.

**Built by Armstrong Ngam** · AWS Solutions Architect – Professional · CompTIA Security+ · M.S. Cybersecurity

> **Status:** Modules 1–3 are built and verified with evidence. Later modules are
> in progress; their code is drafted in this repository, and each one moves to
> "Verified" only after I run it and record the results below.

---

## Verified results

### Host hardening: CIS Level 1 on Rocky Linux 9 (Ansible + OpenSCAP)

Same scanner, same profile (`cis_server_l1`), same datastream (`ssg-rl9-ds.xml`), before and after the `cis_hardening` role.

| Measure | Before | After |
|---|---|---|
| CIS L1 rules passing | 153 | **202** |
| CIS L1 rules failing | 109 | **60** |
| Pass rate | 58% | **77%** |
| Second run of the role | n/a | **`changed=0`** across 31 tasks (idempotent) |

Controls were tested by behavior, not only by scan result:

- Password SSH is refused (`Permission denied (publickey,...)`); key login still works.
- SELinux `Enforcing`; audit rules loaded and immutable (`auditctl -s` → `enabled 2`).
- Firewall exposes `ssh` only (Rocky's default `cockpit` and `dhcpv6-client` removed).
- PAM managed by authselect with `without-nullok` and `with-faillock`.
- Time zone UTC, NTP synchronized; AIDE baseline built with a daily check.

### Secure delivery pipeline (GitHub Actions)

Every pull request must pass these gates; on `main`, images are also published, signed and promoted.

| Gate | Tool | Evidence |
|---|---|---|
| Unit tests and lint | pytest, ruff | Both services, every PR |
| Secret scanning | Gitleaks + GitHub push protection | Drill 1: a fake AWS key on a test branch failed the PR; it never reached `main` |
| Static analysis (SAST) | Semgrep | Results in the Security tab |
| Infrastructure as code | Checkov | Two real findings fixed: tokens moved from env vars to mounted files (CKV_K8S_35), AZ pinned by name (CKV_AWS_394) |
| Container smoke test | docker + curl | Each image starts read-only and must answer `/healthz` before it is scanned or published |
| Image vulnerabilities | Trivy | Fails on fixable HIGH/CRITICAL CVEs |
| SBOM + signing | Syft, Cosign (keyless) | Every image on `main` is signed by this workflow's GitHub identity |
| GitOps promote | kustomize | A bot commits the signed digests to `k8s/`; nobody edits them by hand |

Verify a published image yourself:

```bash
cosign verify ghcr.io/armstrongngam/devsecops-secure-platform/secure-app@sha256:<digest from k8s/app/kustomization.yaml> \
  --certificate-identity-regexp '^https://github.com/armstrongngam/devsecops-secure-platform/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Supply-chain practices: the Trivy action pinned by commit SHA (pinning every third-party action is next); Dependabot covers both services, groups minor and patch updates, and keeps each major update in its own PR; secret scanning with push protection; `main` protected against deletion and force pushes.

### Problems solved along the way

| Problem | Root cause | Fix in code |
|---|---|---|
| First compliance scan "passed" with **zero rules evaluated** | Playbook picked the RHEL datastream; its platform check rejects Rocky, so all 295 rules were `notapplicable` | Choose the datastream from Ansible facts; fail the play if no rules are evaluated |
| Account-lockout setting had **no effect** | `faillock.conf` existed, but PAM was unmanaged on the minimal install, so nothing read it | Role selects an authselect profile with `with-faillock` and `without-nullok`, keeping a backup |
| Dry run failed on the SELinux module | Minimal install lacks the Python bindings Ansible needs on the target | First task installs `python3-libselinux` (runs even in `--check`) |
| Patch run hung for 20 minutes | Updating NetworkManager/OpenSSH dropped Ansible's connection after dnf finished | Confirmed from the console with process and log checks before interrupting; reran safely (idempotent) |
| Unneeded services open after hardening | Role added `ssh` but never removed defaults | Task closes a configurable list of default services |
| Build failed: `trivy-action@0.28.0` could not be resolved | Its tags were deleted after the March 2026 supply-chain compromise of trivy-action | Pinned to the immutable 0.35.0 release by commit SHA; later updated to v0.36.0 only after checking the SHA matched the official tag and descended from the trusted commit |
| Dependabot closed two needed updates as "up-to-date" | Tool error | Checked the files on `main`, confirmed they were outdated, re-triggered the scan |
| AI-triage service received no dependency updates | Dependabot config only watched `/app` | Added `/ai-ops/triage`; grouped minor/patch updates |

## Roadmap

| Module | Scope | Status |
|---|---|---|
| 1 · Foundations | WSL control node, Hyper-V, segmented lab network, Rocky Linux 9 | ✅ Verified |
| 2 · Automation and hardening | Ansible, CIS Level 1 role, OpenSCAP before/after | ✅ Verified |
| 3 · Code and pipeline | GitHub Actions with secret scan, SAST, IaC scan, smoke test, CVE scan, SBOM, keyless signing, GitOps promote | ✅ Verified |
| 3 · Google Cloud track | GCP baseline with Workload Identity Federation; Sigma and YARA-L detections | ⏳ Planned |
| 4 · Segmented lab network | Firewall zones, bastion host, more hardened VMs | ⏳ Planned |
| 5 · Kubernetes and GitOps | k3s, Argo CD, Kyverno signed-image admission | ⏳ Code drafted |
| 6 · Monitoring | Falco, Prometheus, Grafana | ⏳ Code drafted |
| 7 · Detection engineering | Simulated attacks (MITRE ATT&CK), auditd/Falco/Zeek detections, Sigma in CI | ⏳ Planned |
| 8 · Incident response drills | Drills with evidence and post-incident reviews | ⏳ Planned |
| 9 · AI-assisted response | Local LLM triage behind guardrails, human approval for containment, prompt-injection red team | ⏳ Code drafted |
| 10 · Cloud | Terraform for AWS: OIDC, IMDSv2, SSM-only access | ⏳ Code drafted |

## Repository map

```
ansible/             cis_hardening role and OpenSCAP compliance scan   (verified)
.github/workflows/   CI security gates and Terraform plan              (verified)
app/                 Flask API, tests, hardened multi-stage Dockerfile
k8s/                 manifests, Kyverno policies, Argo CD, Falco, monitoring
ai-ops/              AI triage service with guardrails; Event-Driven Ansible
terraform/aws/       VPC, IAM + GitHub OIDC, k3s node, budget
docs/                lab guide, threat model, incident drills, evidence
```

## Run the hardening yourself

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml
cp inventory/hosts.example.ini inventory/hosts.ini     # add your hosts
ansible-playbook compliance.yml -K                     # baseline score
ansible-playbook site.yml --check --diff -K            # preview changes
ansible-playbook site.yml -K                           # apply
ansible-playbook compliance.yml -K                     # after score
```

Take a VM snapshot first, and keep an existing root session open while PAM and SSH change.

## Design decisions

- **Measure before and after with the same tool and profile.** A score is only evidence if the method doesn't change.
- **Verify behavior, not just configuration.** A file existing doesn't mean the control works; every control above was tested directly.
- **Fix in code, not by hand.** Every fix found during testing went back into the role, so the next server gets it automatically.
- **Document exceptions instead of chasing 100%.** Some CIS rules don't fit a lab VM (for example, separate partitions or a GRUB password behind a hypervisor console); each gets a reason.

## License

MIT
