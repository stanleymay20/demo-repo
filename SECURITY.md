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
- whether authorization, scope, provenance, decision integrity, review, audit or replay controls were bypassed;
- logs with secrets and personal data removed.

## Security invariants

A release must fail closed when any of these are missing, invalid or changed between evaluation and execution:

- authoritative tool manifest;
- authorization scope and exact-effect binding;
- live single-use grant;
- action/payload/scope/manifest integrity binding;
- authenticated execution decision (trusted in-process seal or detached Ed25519 signature);
- required human-review approval verified with public keys only;
- supported policy version.

Execution admission is audited after grant consumption and before dispatch. Dispatch success/failure is emitted as a second structured audit event without raw payload/output or exception text. Production deployments must provide durable audit persistence and externally anchor the chain head if tail-truncation detection is required across writer compromise.

Prompt-injection detection is evidence, not authority. Detector failure must not expand the set of host-authorized effects.

## Disclosure

Please allow a reasonable remediation window before public disclosure. Confirmed vulnerabilities will be tracked against the exact affected release and regression-tested before closure.
