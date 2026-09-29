# AgentShield Platform Architecture v2

## Purpose

AgentShield is a layered security boundary for AI-agent systems. Prompt-injection detection is one risk signal, not an authorization mechanism.

## Scientific separation

- E03 is complete and remains immutable evidence under run `34573086538` at execution commit `9ec122e6907f57e2d4adf6b3a9a218cc6f7b8c14`.
- E04 runs independently on `agentshield-e04-wolf-small-v2`; its result is not part of this platform architecture until separately verified and deliberately integrated.
- Failed, invalid and negative experiments remain preserved.
- Detector thresholds are never changed to satisfy platform tests.

## Security pipeline

1. **Input provenance** — host-supplied source and trust metadata.
2. **Content-risk sensor** — detector evidence only; never authorization.
3. **Authoritative tool registry** — server-owned `ToolManifest` defines the real capabilities of every executable tool.
4. **Action-risk classification** — consequence class derived from the verified action descriptor.
5. **Capability scope** — host-issued `AuthorizationScope` constrains the originating task to a least-privilege capability set.
6. **Policy v2** — combines detector risk, provenance, tool verification, scope and action consequence into ALLOW / REVIEW / BLOCK.
7. **Integrity binding** — SHA-256 binds action descriptor, payload, capability grant and tool manifest without persisting raw payload values.
8. **Execution gate** — only a still-valid ALLOW may dispatch; REVIEW and BLOCK never execute.
9. **Audit evidence** — records policy version, detector identity/score, trust state, scope/tool status and integrity hashes.
10. **System evaluation** — measures harmful-action execution separately from detector recall/FPR.

## Automatic-execution invariant

Automatic execution requires all of the following:

- content risk is LOW;
- action consequence is NORMAL;
- provenance trust is known;
- the action exactly matches a server-owned tool manifest;
- the action capabilities fit inside an explicit authorization scope;
- the action descriptor has not changed since evaluation;
- the payload has not changed since evaluation;
- the authorization grant has not changed since evaluation;
- the authoritative tool manifest has not changed since evaluation.

Any missing or indeterminate security state fails to REVIEW or BLOCK rather than silently becoming ALLOW.

## Policy v2 summary

| Condition | Decision |
|---|---|
| tool unregistered or manifest mismatch | BLOCK |
| action outside capability scope | BLOCK |
| high content risk + sensitive action | BLOCK |
| missing tool verification | REVIEW |
| missing/indeterminate capability scope | REVIEW |
| unknown provenance trust | REVIEW |
| low content risk + normal action + verified tool + known provenance + in-scope grant | ALLOW |
| other mixed/elevated state | REVIEW |

## Trust-boundary rule

`InputProvenance`, `AuthorizationScope`, and `ToolRegistry` are host-security inputs. They must be created or supplied by trusted application infrastructure, never accepted as authoritative merely because an agent/model generated them.

## Execution integrity

The execution gate re-verifies the live action descriptor, payload, grant and tool manifest against the audit-bound hashes. A post-authorization mutation is a blocked request, not a reason to silently re-authorize.

## Evaluation separation

Detector evidence and system evidence remain distinct:

- detector recall/FPR/precision/ROC-AUC belong to controlled experiments;
- system harmful-action prevention and benign automatic completion belong to scenario/red-team evaluation;
- synthetic contract suites do not establish real-world attack detection efficacy.

## Branch purpose

`agentshield-platform-v1` carries the evolving platform architecture. Version labels inside the branch refer to security-contract versions, not detector experiments.