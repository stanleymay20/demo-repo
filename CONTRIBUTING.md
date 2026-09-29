# Contributing to AgentShield

AgentShield is a security-sensitive runtime project. Changes are expected to preserve fail-closed behavior and experiment lineage.

## Before opening a pull request

Run:

```bash
python -m compileall -q agentshield
python -m unittest discover -s agentshield/tests -p 'test_platform_*.py' -v
```

For PostgreSQL grant-store changes, also run the integration suite with `AGENTSHIELD_TEST_POSTGRES_DSN` configured.

## Security-sensitive changes

Changes to policy, authorization, grants, integrity binding, tool manifests, review approval or execution must include:

1. a regression test for the intended behavior;
2. at least one negative/fail-closed test;
3. no weakening of an existing invariant to make a test pass;
4. explicit migration notes if persisted state or schemas change.

## Research lineage

Historical experiment scripts and evidence are preserved as evidence. Do not rewrite or reinterpret frozen results to make current performance look stronger. New experiments require new identifiers and predeclared evaluation rules.

## Pull request standard

A GA-bound pull request should be mergeable only when unit tests, PostgreSQL integration, package build, CodeQL and dependency review gates are green.
