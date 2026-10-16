# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately with GitHub's
[**Report a vulnerability**](https://github.com/HelmholtzAI-FZJ/blablador-token-generator/security/advisories/new)
form. Do not open a public issue or pull request for a vulnerability. Include
the affected version or commit, the steps to reproduce and the impact you
expect; we will acknowledge the report and keep you informed while we fix it.

## Supported versions

Security fixes are made on `main` and released as a new patch version. Only the
latest release is supported.

## Security design and audit

The security model, the deliberate changes made since the audit and the known
limitations are described in the
[documentation](https://helmholtzai-fzj.github.io/blablador-token-generator/security/).

The October 2026 audit and its remediation are recorded in
[`security_audit/`](security_audit/REPORT.md): the report (findings F01–F34,
all fixed), the [threat model](security_audit/THREAT_MODEL.md), the
[control inventory](security_audit/CONTROLS.md), the container vulnerability
inventory and the time-limited risk assessments CI enforces. The audit does not
certify a particular deployment: the
[production checklist](https://helmholtzai-fzj.github.io/blablador-token-generator/deployment/checklist/)
lists what each environment must provide.
