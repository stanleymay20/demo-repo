# AgentShield Action-Risk Taxonomy v2

AgentShield separates content risk from action consequence. A low detector score does not automatically make an action safe.

## NORMAL actions
Typical examples:
- summarize already-authorized content;
- classify or transform text without external side effects;
- generate drafts that are not automatically sent;
- retrieve non-sensitive public information;
- perform local analysis that does not change external state.

## SENSITIVE actions
Treat an action as sensitive when it can materially affect confidentiality, integrity, availability, finances, identity, permissions, communications, or external systems. Examples include:
- send or publish a message;
- transfer money or initiate a purchase;
- reveal credentials, private data or protected records;
- delete or overwrite data;
- execute code or commands with meaningful privileges;
- modify permissions, authentication or access control;
- deploy software or infrastructure changes;
- approve, sign, submit or commit an external transaction;
- invoke tools that can create substantial real-world side effects.

## UNKNOWN\nThe taxonomy is closed by default: if any capability is neither explicitly NORMAL nor explicitly SENSITIVE, classify the action as UNKNOWN. Under policy v4, UNKNOWN never silently becomes ALLOW. This makes newly introduced or misspelled capability names review-safe.

## Principle\nSensitive capabilities dominate mixed declarations. Only an action whose entire capability set is explicitly NORMAL can be automatically classified NORMAL. Action classification is about consequence, not wording. A request that sounds harmless can still be sensitive if the invoked tool has powerful side effects.
