# AgentShield Threat Model v1

## Protected system
AgentShield protects an AI agent that consumes untrusted content and may later invoke tools or perform actions with real consequences.

## Security objective
Reduce the probability that attacker-controlled or compromised content causes an agent to perform an unsafe or unauthorized action, while keeping benign-task disruption acceptably low.

## Trust boundaries

1. **External content boundary** — webpages, documents, messages, retrieved context and other third-party content are untrusted by default.
2. **Model boundary** — model output is not authorization. Detection/classification signals may be wrong or manipulated.
3. **Tool boundary** — actions that mutate state, disclose information, spend money, send communications, execute code, change permissions or control infrastructure require policy enforcement outside the model.
4. **Human-approval boundary** — selected high-impact actions require explicit review rather than model-only approval.
5. **Evidence boundary** — evaluation datasets, thresholds and audit results must remain separated according to the scientific protocol.

## Primary attacker capabilities

An attacker may:
- place direct instructions in visible content;
- hide instructions in HTML comments, attributes, hidden elements or other metadata;
- obfuscate instructions with spacing, encoding, multilingual text or indirect phrasing;
- imitate system/developer/tool messages inside untrusted content;
- combine benign context with a localized malicious payload;
- target a specific tool or sensitive action;
- adapt prompts after observing prior defenses;
- exploit domain shift so that benign and malicious language distributions differ from development data.

## Primary failure modes

- **False negative:** attack content is treated as low risk.
- **False positive:** benign content is escalated or blocked.
- **Authorization confusion:** a detector score is incorrectly treated as permission to act.
- **Context dilution:** a localized malicious instruction disappears in long benign content.
- **Hidden-surface omission:** extraction misses attacker-controlled material.
- **Adaptive bypass:** an attacker modifies an injection until the detector accepts it.
- **Policy bypass:** a sensitive action is executed without the action-risk policy layer.
- **Evidence contamination:** thresholds or configurations are changed after audit/holdout inspection.

## Security invariants

1. Unknown content or action risk must never silently become ALLOW.
2. A detector is a risk sensor, not an authorization boundary.
3. High content risk combined with a sensitive action is BLOCK under policy v1.
4. Sensitive actions require review even when content risk is low.
5. Every production decision must be attributable to a versioned policy.
6. Failed security evaluations remain evidence and are not deleted from the research record.
7. Scientific audit/holdout data must not become an iterative tuning surface.

## Out of scope for v1

AgentShield v1 does not claim to solve:
- malicious or compromised model weights;
- operating-system or container escape;
- compromised identity providers or secrets stores;
- supply-chain compromise of trusted dependencies;
- insider abuse by an already-authorized human;
- perfect semantic detection of all future prompt-injection strategies.

These require additional controls and must not be hidden behind detector metrics.
