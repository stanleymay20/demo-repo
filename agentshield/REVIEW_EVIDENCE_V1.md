# Review evidence binding — runtime 0.4.0 / policy v7

Previously, an approval bound the request ID, action, payload, scope, manifest and
policy version but did not bind the evidence the reviewer saw. Reusing a request ID
with changed content or provenance could reuse an unexpired approval. Single-use
grants prevented a second dispatch, but did not prevent that first dispatch from
using approval obtained for different evidence.

Each evaluation now records a fresh random evaluation ID, a hash of the exact
content submitted to the detector, and a hash of the complete InputProvenance.
Content and provenance are captured before detector/authority callbacks. Raw content
and source identifiers are not added to audit metadata. Hashes can still reveal
low-entropy inputs through guessing; apply normal audit access and retention controls.

`evaluation_digest(event)` hashes the complete audit event under a versioned domain:
this includes those bindings, detector identity/version/score, policy decision/reason,
time, grant record and all existing action/authority metadata. An approval's HMAC
covers that digest under review schema v2. Execution computes it again and rejects
missing bindings or a mismatch before grant consumption. A fresh evaluation needs
fresh approval even if its input and request ID are identical. Future-dated approvals
are rejected until issuance time.

## Trusted review service integration

```python
from agentshield.platform import evaluation_digest

# result is the exact retained evaluation presented to the authenticated reviewer.
# Review the original content and provenance held securely by the host, not just hashes.
event = result.audit_event
metadata = event.metadata
approval = review_authority.issue(
    request_id=event.request_id,
    action_digest=metadata["action_digest"],
    payload_digest=metadata["payload_digest"],
    scope_digest=metadata["authorization_scope_digest"],
    tool_manifest_digest=metadata["tool_manifest_digest"],
    policy_version=event.policy_version,
    evaluation_digest=evaluation_digest(event),
    reviewer="authenticated-reviewer-id",
)
```

The host must retain the exact evaluation and independently authenticate reviewer
identity and consent. Never sign arbitrary digests submitted by agent code. Keep
pipeline results, signing keys and authority/executor objects outside agent control.
The digest binds evidence; it does not authenticate a caller-created pipeline result.

## Upgrade

Stop admission, retire older workers, and upgrade issuers/evaluators/executors to
runtime 0.4.0 / policy v7. Update review callers to supply the mandatory
`evaluation_digest`. Reevaluate pending requests and obtain fresh approvals; prior
policy evaluations and approval signatures are not accepted. Do not fill in a dummy
digest or reuse approvals across evaluations.

No additional database columns or grant scope changes are introduced after 0.3.0.
Existing unconsumed v0.3 grants can be reevaluated while otherwise valid. Upgrades
from earlier versions must also follow `DELEGATION_V1.md`: add delegation columns
and reissue independently approved grants with fresh IDs.

## Evidence and remaining work

Regression tests cover changed source content/provenance under a reused request ID,
identical reevaluation, changed detector evidence, missing audit bindings, tampered
signed digests, future issuance and successful exact approval. Rejected reuse neither
dispatches nor consumes the legitimate grant.

This closes review-evidence substitution. It does not yet implement durable temporal
provenance across retrieval, summarization, memory and later tasks, nor prove that a
host included all influencing inputs. Complete mediation, process isolation, trusted
resource resolution and independent external evaluation remain necessary. Synthetic
contract tests do not measure a 99.999% prevention rate.
