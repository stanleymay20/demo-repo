# AgentShield Security Policy

AgentShield sits on an execution trust boundary. Security reports should therefore be handled privately and with enough detail to reproduce the issue without publishing a working exploit before a fix is available.

## Supported release line

Until the first GA tag is cut, the supported line is the current GA-hardening branch and its successor on `main`.

## Reporting a vulnerability

Do **not** open a public issue containing exploit details, credentials, private data or a weaponized prompt/tool sequence.

Use GitHub private vulnerability reporting / a private security advisory when it is available for this repository. If private reporting is not available, contact the repository owner through GitHub before public disclosure.

Please include:

- affected commit or release;
- threat model and trust boundary crossed;
- minimal reproduction;
- whether a tool side effect actually occurred;
- whether authorization, scope, provenance, integrity, review or replay controls were bypassed;
- logs with secrets and personal data removed.

## Security invariants

A release must fail closed when any of these are missing, invalid or changed between evaluation and execution:

- authoritative tool manifest;
- authorization scope;
- live grant;
- action/payload/scope/manifest integrity binding;
- required human-review approval;
- known policy decision.

Prompt-injection detection is evidence, not authority.

## Disclosure

Please allow a reasonable remediation window before public disclosure. Confirmed vulnerabilities will be tracked against the exact affected release and regression-tested before closure.
