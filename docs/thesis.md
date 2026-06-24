# What this is for — the thesis

> North-star document. The README says *what* this repo does and refuses to do;
> this says *why*, and where it sits in a field that — as of 2026 — is converging
> on the same ideas from several directions. Read [scope-and-boundaries.md](scope-and-boundaries.md)
> for the issuance/consumption line this thesis assumes.

## The one sentence

The neutral **origin** of portable, self-owned agent identity that personal and
custom agents both carry and that **no consuming system owns** — so we don't
repeat, for agents, the mistake we made giving IdPs ownership of human identity.

## The mistake we're not repeating

Human identity got captured by IdPs ("log in with Google") for a *structural*
reason: humans can't hold their own keys or manage their own identity, so we
handed it to an IdP, which then owned it. The identifier ate the identity.

Agents don't have that limitation. They hold their own keys. So the reason for
the capture **doesn't apply** — repeating it for agents is a choice, not an
inheritance, and a bad one. This is the twin of the project's founding line —
*"a wallet exists because humans can't sign; agents can."* That was the **custody**
corollary. This is the **ownership** corollary. Same root (agents hold keys), two
consequences: no wallet, and no IdP-owner.

## Identity vs. identifier

- **Identity** — durable, portable, self-owned (the agent holds its keys),
  vouched by a neutral origin, travels across every context. Owned by the
  agent/principal.
- **Identifier** — a local handle a system assigns to *reference* an identity in
  its own namespace, to hang state and decisions on. Owned by the system,
  disposable.

**The rule: identifier → identity.** Systems mint identifiers freely (a SpiceDB
object id, a `sub_hash`, a database row). The moment a system's identifier *is*
the identity, the capture is back.

## Identity is acquired on need, not at birth

"Birthright identity" is the wrong frame. There are three moments:

- **Keypair — at birth.** Self-minted, no authority, free. The only true
  birthright. The agent can always say "I am this key" and prove it — but that's
  an identifier asserting itself, bytes, not trust.
- **Vouch / charter — when provisioning for a purpose.** Lazy relative to birth.
- **Trust — at first contact.** The relying party's call, made in the moment.

The registry lives at the **vouch** layer, invoked around contact — not at birth.
Because identity is created only at the moment of a consumption event, it is
**demand-pulled**: you cannot mint it into a void. (That is the structural answer
to the issue-into-a-void / adoption-graveyard risk.)

**Agents should get identity the way servers do, not the way captured humans do.**
A server self-asserts a name + key; trust is conferred contextually — by a CA *and*
by the client choosing to connect, at connect time. Lazy, presented, relying-party
decided. The birthright/IdP model is the captured-human model: eager, owned, binary.

### The interaction shape

```
introduce   → identifier + proof of key control   (the shared primitive)
[vouch]     → charter, IF the relying party wants more than TOFU
request     → carries intent (why this action, now)
decide      → graduated, relying-party-owned:
              anonymous / pin (TOFU) / demand-vouch / issue-credential / deny
```

The amount of identity required is itself a function of the ask. That graduated,
consumer-owned response is richer than binary authenticated/not — and it is the
correct locus of authority (the consumer decides, the IdP doesn't decide for it).

The honest limit: first contact has no prior trust, so it bottoms out at **TOFU
or a pre-existing vouch**. The vouch is eager relative to contact, lazy relative
to birth. The registry doesn't vanish; it relocates from birth to need.

## Personal and custom agents, reconciled

They differ in exactly **one** place — *who vouches at enrollment*:

- **Personal agent** (e.g. a roaming assistant): vouched by its person — the human
  attests "this is my agent" (`sub`=human, the delegation).
- **Custom agent** (e.g. a deployed workload): vouched by its operator.

After that they are identical: each carries a portable identity + charter; each
system it enters mints a local identifier bound to that identity and hangs its own
decisions there. The reconciliation seam already exists in code — the voucher's
**pluggable trusted-issuer set** (`app/voucher.py`) is where the second signer
plugs in. Person-vouched and operator-vouched go through the same endpoint with a
different signer.

## Consumption is projection into the substrate

The identity is self-owned upstream; at each consumption edge it is **projected**
into whatever that substrate requires:

- resource server → an **OAuth bearer**, via token exchange (`act.sub` carries the
  durable identity; the bearer is the disposable local projection)
- ATProto / Watershed → a native record/handle construct
- a peer agent → a presented VP

Projection is not a defeat and not a transfer of ownership — it is the
identifier→identity rule applied to *credentials*. The one consumption primitive
that is genuinely shared and necessary across every substrate is **proof of
control** (`present()` / `verify()`): how a self-owned identity becomes a system's
trustable local identifier without the system owning it.

## Where this sits in 2026 (related work — link, don't reinvent)

The field is converging on these ideas from several directions. This repo should
**map onto** these, not duplicate their primitives. Its durable value is the
synthesis above plus the consumption adapters — not a bespoke issuer.

- **Open Agent Passport (OAP)** — DID-based identity + declarative
  capabilities/limits, issuer-signed, layered on MCP/A2A/VC. Closest to this whole
  thesis. <https://cubitrek.com/blog/agent-passport>
- **AGNTCY Agent Identity** (Cisco/Outshift, "Internet of Agents") — DID-bound
  agent ID + provenance + attachable VCs.
  <https://outshift.cisco.com/blog/ai-agent-identity-framework-agntcy> ·
  <https://docs.agntcy.org/identity/credentials/>
- **IETF `draft-oauth-transaction-tokens-for-agents`** — OAuth transaction tokens
  with `actor`/`principal` for agent context across service boundaries. The
  *correct* form of the OAuth-edge projection above; adopt rather than hand-build.
  <https://datatracker.ietf.org/doc/html/draft-oauth-transaction-tokens-for-agents-04>
- **A2A + DIF presentation exchange** — VC exchange built into agent-to-agent;
  the lazy present-and-decide pattern as a wire protocol.
- **WIMSE / AIMS / SPIFFE-for-agents** — the workload/custom-agent side, and the
  named gap this charter fills: *SPIFFE says "this workload is X"; it cannot say
  "X, acting for Y, with limited scope, for bounded time, with audit."*
  <https://stacklok.com/blog/agentic-identity-explained-how-to-apply-spiffe-and-relationship-based-authorization-to-ai-agents-in-2026/>
- **UCAN** — capability/attenuation/delegation; note known weaknesses (DID
  complexity, nested-JWT token bloat) before adopting.
- **Delegation-chain splicing** (2026 OAuth WG) — independent confirmation that an
  agent's slice needs *independent* bounding (bind subject + actor tokens to the
  same request).
- **MCP 2026-07-28 authorization** — OAuth 2.1 + RFC 9728/9207; the bearer edge is
  the mandated interop substrate, which is why projection (not replacement) is the
  game. <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- **DIF — "Authorising Autonomous Agents at Scale."**
  <https://blog.identity.foundation/building-ai-trust-at-scale-4/>

## Honest calibration

Not foolish — **early, and deliberately built to fail cheap if it is.** The
conception is the correct application of "agents can hold their own keys" to
identity *ownership*. The risk is purely timing and a crowded, unconverged field.
The lazy/need-based model *is* the hedge: no inventory minted, manufactured on
demand, so being early costs ~nothing. The failure mode to avoid is reinventing
primitives that are being standardized; the durable contribution is the synthesis
and the closed-loop demos that prove it against real consumers you own.
