# AgentShield GA Readiness Contract

This document separates **runtime-platform GA** from **detector research claims**.

## Runtime GA invariants

A GA release must demonstrate all of the following on the exact release commit:

- fail-closed ALLOW / REVIEW / BLOCK policy;
- server-owned tool manifests;
- least-privilege authorization scopes;
- mandatory exact-effect authorization and rejection of resource/destination changes,
  including attempts to expand an issued effect allowlist;
- durable atomic grant verification/consumption across workers;
- replay, expiry and revocation enforcement;
- action, payload, scope and manifest integrity binding;
- detached strict-JSON payload snapshots across evaluation and dispatch, including
  mutation-during-consumption and Python/JSON type-alias adversarial regressions;
- cryptographically bound, short-lived human-review approval for REVIEW resumes;
- tamper-evident audit envelopes with signing-key rotation support;
- no raw untrusted payload persistence by default;
- package install/build smoke test;
- Python unit tests and PostgreSQL concurrency integration tests;
- CodeQL and dependency-review gates;
- immutable-SHA GitHub Action references in GA workflows;
- documented security reporting and contribution rules.

## Detector / research claim boundary

The runtime can be released independently of a universal prompt-injection claim. Detector metrics must remain attached to their exact frozen protocol and dataset. Historical internal audit data is corroborating evidence, not a pristine external holdout.

A detector marketed as production-validated still requires a genuinely unseen contamination-screened external holdout, predeclared gates, confidence intervals and independent adversarial reproduction.

## Administrative release gates

Before the first GA tag:

- make `main` the canonical AgentShield implementation;
- require the GA workflow and CodeQL checks on protected `main`;
- require pull-request review for security-sensitive changes;
- enable secret scanning / push protection where the GitHub plan supports it;
- choose and add the repository license;
- decide whether to rename the legacy `demo-repo` repository;
- create an annotated release tag and preserve its build artifacts/SBOM/provenance.

These repository-admin controls are release gates even though they are not runtime code.
