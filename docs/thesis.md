# What this is for

The README covers what the repo does. This covers why, and how it relates to work
happening elsewhere in 2026. See [scope-and-boundaries.md](scope-and-boundaries.md)
for the issuance/consumption split it assumes.

## Purpose

Agents do not need an identity of their own. They need a key they control, and a
vouched representation of their nature that each service can evaluate on its own
terms. This repo issues that representation. The point is to give a service enough
to decide without an IdP owning the agent, and so to avoid repeating, for agents,
the mistake we made when we let IdPs own human identity.

"Identity" is the wrong word for what an agent needs, and using it costs you the
argument before it starts: say agents need identity and people hear that agents need
accounts. What a service actually wants to know is what this thing is and what it is
for, not who it is.

## The mistake we're not repeating

Human identity ended up owned by IdPs ("log in with Google") for a practical
reason: people can't hold their own keys or manage their own identity, so we
handed that job to an IdP, and the IdP became the owner. The identifier became the
identity.

Agents don't have that limitation. They hold their own keys, so the reason the
capture happened doesn't apply to them. Repeating it would be a choice, not a
necessity. This is the point the project started from ("a wallet exists because
humans can't sign; agents can"), applied to ownership instead of custody: one
cause (agents hold their own keys), two results (no wallet, no IdP owner).

## What the agent actually owns

Four layers, with different owners and different lifetimes. Collapsing them is where
the confusion lives:

| Layer | Owned by | Lifetime |
|---|---|---|
| Key | the agent | durable; the only real birthright |
| DID | the registry's namespace | survives key rotation; dies with the registry |
| Charter | operator vouches, registry signs | minted on need, `CHARTER_TTL_DAYS` |
| Projection | the verifier | one presentation |

Only the first is genuinely the agent's own. Everything above it is representation,
and representation is allowed to be plural: nothing stops two registries issuing
against the same key, one saying the agent may publish and another certifying it for
something else. The key is the join point. The repo issues a single charter today,
so that is a property of the model before it is a property of the code.

The old rule survives with a sharper target: an identifier points at a key. Systems
mint identifiers freely, a SpiceDB object id, a `sub_hash`, a database row, and the
DID is one of them too. The trouble starts when a system's identifier becomes the
thing itself, because then the capture is back.

Tailoring happens at the bottom layer, not the top. The agent holds one charter and
each service sees a cut of it sized to what that service needs to decide, which is
what SD-JWT-VC selective disclosure in `app/jwt_vc.py` is for. A second service does
not mean a second identity or a second charter.

### The identifier is hosted, and that is a real dependency

This repo issues `did:web`, not `did:key`, and the difference decides who owns the
identifier.

With `did:key` the identifier is the key. Fully self-rooted, no infrastructure, and
nobody can take it away. But rotating the key means a new identifier, so continuity
breaks, and there is nowhere to publish revocation.

With `did:web` the identifier is a hosted location resolving to a document that
contains the key. The identifier then survives key rotation, which is why
`POST /agents/{id}/rotate` can exist at all, and revocation has somewhere to live.

The price is that the durable identifier depends on a domain continuing to resolve.
If the registry disappears, the agent still holds its key but its identifier is dead.
So the key is the agent's own and the identifier is hosted, and "self-owned" should
not be claimed for both.

A verifier that wants none of that dependency can pin the key rather than the DID.
After first contact the registry becomes advisory, which is the cheapest anti-capture
measure available and costs nothing to offer.

### Is the registry an IdP?

Partly, and it is worth naming exactly where rather than asserting it isn't.

| | an IdP | this registry |
|---|---|---|
| Holds the credential | yes, signs on your behalf | no, the agent signs |
| In the request path | yes | no, issuance only |
| Owns the namespace | yes | yes |
| Identity survives leaving | no | no |

Two of four. Not an IdP on custody or on request-path involvement, and squarely one
on namespace and survivability. The `did:web` choice is what puts it there.

The distinction that does hold is narrower than "we are not an IdP," and it is this:
the registry owns a name, not a capability. It can stop naming an agent. It cannot
stop that agent proving it is the same agent, because the key is not the registry's
to revoke. So an agent can enrol at a second registry with the same key, take a new
DID in that namespace, and demonstrate continuity across both. Services that pinned
the old DID have to decide whether to accept the link, but the link is provable.

A human cannot do this. Nobody walks out of an IdP and demonstrates cryptographically
to the next one that they are the same person, which is why for humans the name is
the identity: there is nothing underneath it. For agents there is a key underneath,
so the name is detachable. That is the whole argument, and it is the reason this
registry can own a namespace without the capture following.

## Identity is acquired on need, not at birth

"Birthright identity" is the wrong frame. There are three moments:

- A keypair, at birth. Self-minted, free, no authority required. It's the only
  real birthright, but it's just an identifier asserting itself: bytes, not trust.
- A vouch or charter, when the agent is provisioned for a purpose. Later than birth.
- Trust, at first contact. The relying party decides in the moment.

The registry sits at the vouch layer, not at birth. Identity is created only when
something is about to consume it, which means it is demand-pulled and can't be
minted into a void. That is also the answer to the adoption-graveyard risk.

Agents should get identity the way servers do, not the way captured humans do. A
server asserts a name and a key, and trust is conferred in context: by a CA, and
by the client choosing to connect, at connect time. The birthright/IdP model is
the human-capture model, which is eager, owned, and binary.

### The interaction

```
introduce   → identifier + proof of key control
[vouch]     → charter, if the relying party wants more than TOFU
request     → carries intent (why this action, now)
decide      → relying party's call:
              anonymous / pin (TOFU) / demand vouch / issue credential / deny
```

How much identity is required depends on what's being asked, and the relying party
makes that call. That is more useful than a binary authenticated-or-not, and it
puts the decision where it belongs.

One limit worth stating plainly: first contact has no prior trust, so it comes
down to either TOFU or a pre-existing vouch. The vouch is early relative to
contact and late relative to birth. The registry doesn't disappear; it moves from
birth to need.

## Personal and custom agents

They differ in one place: who vouches at enrollment.

- A personal agent (a roaming assistant, say) is vouched by its person. The human
  attests that this is their agent (`sub`=human, the delegation).
- A custom agent (a deployed workload) is vouched by its operator.

After that they behave the same. Each carries a portable identity and charter, and
each system it enters mints a local identifier bound to that identity. The code
already supports both: the voucher's pluggable trusted-issuer set
(`app/voucher.py`) is where the second signer plugs in. Person-vouched and
operator-vouched enrollments use the same endpoint with a different signer.

## Consumption is projection

This is the fourth layer in practice. At each consumption edge the charter is
projected into whatever that substrate needs:

- a resource server takes an OAuth bearer, via token exchange (`act.sub` carries
  the durable identifier; the bearer is the disposable local projection)
- ATProto/Watershed takes a native record or handle
- a peer agent takes a presented VP

Projection isn't a defeat or a transfer of ownership. It is the
identifier-points-at-a-key rule applied to credentials. The one primitive shared
across every substrate is proof of control (`present()` / `verify()`): it is how a
key the agent controls becomes a system's trustable local identifier without the
system owning the agent.

## Two-sided authority

A delegated token has two subjects: `sub` (the human) and `act` (the agent). It is
a join of two independently-sourced identities, so it needs an authority on each
side, not one. This is why an agent-charter registry sits alongside a human
identity/relationship store rather than inside it.

The two sides are not symmetric. They differ in kind, which is why one registry
can't serve both:

| | `sub` side (human) | `act` side (agent) |
|---|---|---|
| Enrollment | account, IdP-managed | self-held key, voucher-enrolled |
| Keys | held by an IdP | held by the agent |
| Authority | entitlements / relationships (ReBAC) | a declared charter (a ceiling) |
| Maturity | solved (e.g. PingOne + SpiceDB) | the new part (this registry) |

Force the agent onto the human side, as an entity row keyed by a `sub_hash`, and
you lose what makes the agent side work: a key the agent holds, portability across
namespaces, an identifier that only points. You wouldn't put humans on the agent side either,
since they already have accounts and can't hold keys. Each side has its own nature
and its own registry.

The token exchange is where the two meet, which is why RFC 8693 is the right
primitive: it exists to join tokens from different domains. `sub`/`act` is not
only delegation notation; it is the seam between the human-identity world and the
agent-identity world.

Both registries bracket the token. They are consulted going in, to scope the mint
(the agent presents its charter, the human presents an IdP token), and coming out,
at enforcement (the PDP reads the charter via `/resolve` and the human's grants
from the ReBAC store).

```
  act (agent) side              join               sub (human) side
  this registry:            token exchange         IdP + ReBAC store:
  DID + charter        ──►    (RFC 8693)    ◄──    identity + grants + delegation
                                  │
                                  ▼
                       PDP: intersect both sides, per request
```

Nothing in the middle is new. The registry supplies the agent side, the human side
is a solved system you already run, and the PDP intersects them. What's left is
modeling the delegation in the ReBAC store and writing the intersection policy.

## Exchange or presentation

The question people arrive with is "why not just use plain JWTs?", and the
comparison worth making is against RFC 8693 token exchange with `subject_token` and
`actor_token`, because that is the incumbent, it is deployed, and it works. If this
project can't say precisely what it adds, it is only machinery. Inside a single
trust domain it adds nothing: when one IdP issues or federates both sides and mints
the result, a DID is a second trust root and an extra resolution step for a problem
that domain doesn't have. The four cases in
[When any of this is load-bearing](#when-any-of-this-is-load-bearing) are where the
comparison starts to matter.

But the question is framed wrong, so discard the format first. Both sides are JWTs.
A charter issues as `vc+jwt`, an `actor_token` is a JWT, both carry `iss`, both are
signed, and both can be verified by anyone who can reach the key. Nothing here turns
on the encoding. What differs is what the surrounding protocol requires be done with
them.

Three things get claimed for credentials that are really claims about something
else:

- **"The credential is self-describing; a JWT needs pre-configuration."** A JWT
  carries `iss` in the body and `kid` in the header. Standard validation reads
  `iss`, fetches `.well-known/openid-configuration`, takes `jwks_uri`, and
  verifies. That is the same shape as resolving a `did:web` and checking the DID
  document. Both use the token's own contents to find the key that validates the
  token.
- **"Any issuer can present it, and the verifier just checks the token."** Anyone
  can mint a DID and sign a charter claiming `capabilities: [admin]`, and it will
  verify perfectly: signature valid, key resolves, structure conformant.
  Verification is self-contained; trust is not. A verifier that accepts any
  well-formed credential is an open door with good cryptography on it.
- **"Granular decisions need credentials."** They need a policy engine, and the
  claims still in front of it. `if this issuer and this agent and this capability,
  then this token shape` can be written against plain JWT claims by any PDP,
  provided the PDP can still see them.

That last clause is the whole argument.

### The actual axis

In an exchange, an intermediary validates the issuer and mints a new token. That
token is a decision, already taken; everything downstream inherits it and can only
narrow. In a presentation, the credential arrives at the decision point intact, no
decision has been taken yet, and every field in it is available as input.

The trust check at an STS has four properties:

| | |
|---|---|
| mandatory | no token without it |
| prior | resolved before the request is known |
| binary | pass or fail, no gradation |
| remote | at the STS, not at the decision point |

*Prior* is the one that costs you. The issuer term is bound and consumed before the
claims exist as decision input, so a joint decision over issuer, claims, and context
is never available: one of those variables was answered upstream, by something that
did not know what would be asked. That is the same observation as saying the issuer
is a gate rather than a term, seen from the other side. See
[charter-mapping.md](charter-mapping.md) for the resulting mint rule
(`azd ⊆ charter.can`).

Presentation defers the decision instead of front-loading it, and deferral is what
buys the choice. It is not a property of VCs. Hand a raw JWT to a PDP as evidence
rather than exchanging it and you get the same deferral. The ecosystems differ far
more than the formats do: credential tooling assumes presentation, OAuth tooling
assumes an STS.

### What the charter adds on top

Deferral is topology, and any format can have it. The charter contributes something
separate: provenance.

Token exchange is structurally two-party: the verifier trusts the issuer, and the
issuer vouches for the actor. Be careful what that does and doesn't imply.
Federation already scales across agents perfectly well: trust a workload issuer once
and every agent it vouches for is accepted, with no per-agent registration at the
relying party. Per-agent administration exists in both models and sits upstream in
both, as a service account, a SPIRE entry, or an enrollment voucher. Counting
configurations is not the argument.

The difference is what the token carries. A federated workload token authenticates
and stops: it says this is workload X at issuer Y, and says nothing about what X may
do. The ceiling has to live somewhere else, as a mapping from identifier to
permitted scope that the relying party maintains. Trusting the issuer bought
identity, not authority. A charter carries the ceiling as claims signed by the
operator, so it travels with the agent.

That scales on verifiers, not on agents. One relying party maintaining one
identifier-to-scope table is unremarkable; it is just an authorization system. Five
relying parties each maintaining their own answer to "what may agent X do" is five
copies of a fact the operator already knows and has already signed, drifting
independently.

### The bill

The trust list is work that federation was doing for you. Someone has to curate it,
and revocation becomes an explicit fetch (`/resolve`, the status list) rather than
something that falls out of short token lifetimes. There is no widely-deployed
trust framework for credential issuers, nothing playing the role OIDC federation
plays. For one issuer you run yourself this is trivial. At ten issuers you don't
control it is a governance problem, and federation may be the better answer.

## When the issuer matters

The gate-to-term move has a further step. Once the issuer is a term, the allowlist
stops being a separate artifact and becomes policy, and policy can be proportionate
to what is being asked. A pre-configured gate fires before it knows the stakes. A
policy knows the whole request:

- known issuer, `publish` → permit
- unknown issuer, read-only, low-value resource → permit and log, don't pin
- known issuer, `admin` → permit only with a fresh human approval

That is "the relying party decides in the moment" made operational. It is also the
honest answer to the claim that a credential can be verified from anywhere. You can,
and what makes that safe is the policy bounding what a credential of unknown
provenance is allowed to reach.

Trust still has to ground somewhere, and only one of the options genuinely removes
the enumeration:

- Enumerate the issuers in policy. A real improvement, since it is versioned with
  the rest of the rules and evaluated alongside context, but it is the map
  relocated, not removed.
- Chain to an anchor. The issuer presents its own credential from something already
  trusted, so one entry covers many issuers. This is x509 with extra steps, and it
  works.
- Evaluate a property rather than an identity: the issuer's domain matches the
  resource owner, or the issuer is the tenant. Genuine dissolution, but only where
  such a property exists.
- Accept unknown provenance and bound the blast radius instead. Enumeration cannot
  express this, and it is what makes the other three optional.

### How much issuer do you actually need

Proof of key control is issuer-independent. A DID and a signature establish that the
same entity is back, which is enough for continuity, audit, rate limiting, and
pinning. Nobody considers SSH broken for lacking a CA. The issuer only enters when
you are relying on something it asserted, and it matters in proportion to how much
work that assertion is doing.

- Identifier only. The credential provides continuity, not authority. The issuer is
  irrelevant and checking it is ceremony.
- Corroborated. Recall that `allowed = charter ∩ grant ∩ policy`. A forged charter
  claiming `admin` does not get admin; it gets clamped by the other terms. The
  charter's integrity therefore matters in proportion to how far it is the binding
  constraint. Where the human's grant is already narrow, a lying charter buys an
  attacker very little.
- Sole source. The charter is the tightest term, or the only one: agent-to-agent
  with no human in the loop, or a powerful principal where the charter's narrowing
  is the actual restraint. Here the issuer is the whole basis of the decision.

Skipping the issuer check is sound as a decision and dangerous as an omission, and
the two are indistinguishable in the code. It also decays. Extend the charter to
gate a new capability and it quietly becomes the binding constraint, at which point
a policy that was correct on Tuesday is a hole on Friday. If you skip the check,
record why next to the policy, because the fact that made it safe is a fact about
the other terms in the intersection, not about the credential.

This is the Regime A move applied one level up. Regime A removes the boundary rather
than securing it, where the session already carries what is needed. Here the vouch
earns its keep only where its claims are doing real work, and the rest of the time a
stable identifier is the whole requirement. Identity on need, turned on the issuer
instead of the agent.

## Where this sits in 2026

The same ideas are being worked on from several directions. The repo should map
onto that work rather than duplicate it; its value is the synthesis and the
consumption adapters, not a bespoke issuer.

- **Open Agent Passport (OAP)** — DID-based identity plus declarative
  capabilities/limits, issuer-signed, layered on MCP/A2A/VC. Closest to this whole
  thesis. <https://cubitrek.com/blog/agent-passport>
- **AGNTCY Agent Identity** (Cisco/Outshift, "Internet of Agents") — DID-bound
  agent ID plus provenance and attachable VCs.
  <https://outshift.cisco.com/blog/ai-agent-identity-framework-agntcy> ·
  <https://docs.agntcy.org/identity/credentials/>
- **IETF `draft-oauth-transaction-tokens-for-agents`** — OAuth transaction tokens
  with `actor`/`principal` for agent context across service boundaries. The right
  form of the OAuth-edge projection above; adopt rather than hand-build.
  <https://datatracker.ietf.org/doc/html/draft-oauth-transaction-tokens-for-agents-04>
- **A2A + DIF presentation exchange** — VC exchange built into agent-to-agent; the
  present-and-decide pattern as a wire protocol.
- **WIMSE / AIMS / SPIFFE-for-agents** — the workload/custom-agent side, and the
  gap this charter fills: SPIFFE says "this workload is X" but not "X, acting for
  Y, with limited scope, for bounded time, with audit."
  <https://stacklok.com/blog/agentic-identity-explained-how-to-apply-spiffe-and-relationship-based-authorization-to-ai-agents-in-2026/>
- **UCAN** — capability, attenuation, and delegation; note the known weaknesses
  (DID complexity, nested-JWT token bloat) before adopting.
- **Delegation-chain splicing** (2026 OAuth WG) — independent confirmation that an
  agent's slice needs its own bounding (bind subject and actor tokens to the same
  request).
- **MCP 2026-07-28 authorization** — OAuth 2.1 plus RFC 9728/9207; the bearer edge
  is the mandated interop substrate, which is why projection, not replacement, is
  the game. <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- **DIF, "Authorising Autonomous Agents at Scale."**
  <https://blog.identity.foundation/building-ai-trust-at-scale-4/>

## When any of this is load-bearing

Agent identity isn't always needed. The cheapest way to secure a boundary is to
remove it, and a lot of agent interaction does exactly that. There are two
regimes, and most of this document applies only to the second.

Regime A is visibility plus confirmation. The agent shares the human's live
session and view: in-page, same-origin, synchronous, like a WebMCP tool called in
the user's authenticated browser session. It is governed by watching (a live tool
console) and confirming (elicitation or step-up). There is no agent-distinct
principal; the action authorizes from `sub` (the user), `client_id` (the app), and
request context. Reference: `WebMCP-Demo-Retail`.

Regime B is identity plus policy. The agent acts where it can't be watched:
server-side, asynchronous, cross-service, or agent-to-agent. It is governed by who
it is and what it is chartered for. Reference: Notflux plus this registry.

The line between them is whether the human can see and confirm the action. It is
about session co-presence, not autonomy.

Three things keep the line honest:

- WebMCP doesn't solve agent identity; it removes the need for it in Regime A.
  There is no agent-distinct principal to identify.
- `client_id` proves the channel, not the actor: which app, not which agent. That
  holds while the page is a trusted single-agent environment, but it can't tell a
  real assistant from a prompt-injected or third-party agent in the same session.
- The PDP is the same across the line. The same decision (PingOne Authorize, say)
  runs in both regimes; only the subject richness changes, from `(user, channel)`
  in A to `(user, agent, delegation, charter)` in B. Agent identity is extra input
  to the same decision, added when the session can't carry it, not a separate
  system.

Four cases the collapse can't reach, where Regime B is forced:

1. Cross-service fan-out: the second hop, where the session/token audience doesn't
   transfer.
2. Async or detached work: no live session to ride.
3. Server-side or headless agents: no browser session to inhabit.
4. Agent-to-agent: no human session runs through it.

Plus attribution for high-consequence actions even in-session, when you need "the
human's agent did this" rather than "the human did this," for audit or liability.

HITL and on-behalf-of don't belong to one regime; they are cheap in A and need the
apparatus in B. In Regime A, on-behalf-of is implicit (the agent is the session)
and HITL is inline (elicitation). In Regime B, on-behalf-of has to be encoded in a
credential (`sub`/`act`, a transaction token), and HITL becomes out-of-band
approval (CIBA or push) on top of agent identity.

Design from the decision and the oversight backward. Let boundaries collapse where
they can (Regime A), and provision identity minimally and on-need only for the
rest (Regime B). WebMCP routing around identity isn't a threat; it is a filter that
shows where identity is actually load-bearing.

## Calibration

The idea is early, and built to fail cheap if it turns out to be too early. It is
the correct application of "agents can hold their own keys" to ownership. The risk
is timing and a crowded, unsettled field. The on-need model is the hedge: nothing
is minted in advance, so being early costs little. The failure mode to avoid is
rebuilding primitives that are being standardized. The durable part is the
synthesis and the closed-loop demos that prove it against consumers you actually
run.

One assumption worth naming, because it is load-bearing throughout and never argued
for. This document takes it as given that authority is evaluated at use time, by the
relying party, against claims presented in a token. Which engine does the evaluating
is deliberately out of scope: an enterprise PDP, a peer agent checking two
signatures offline, and a PDS accepting a record are all the same shape here, and
[scope-and-boundaries.md](scope-and-boundaries.md) exists to stop any particular one
of them leaking in. The commitment is to the evaluation, not to the evaluator.

There are designs that reject it. In an object-capability system, possession of an
unforgeable reference is the authority, so at use time there is nothing to check: no
identifier, no claim, no decision. Attestation-first designs care what the code is
rather than what it asserts about itself. A charter is squarely a claims-model
artifact, since `capabilities: [publish]` is an assertion someone has to evaluate,
where an object-capability design would hand over an unforgeable publish reference
and leave nothing to evaluate. This document never argues that claims beat
capabilities; it assumes it. That is the place to attack the argument, and it is why
the UCAN entry above is underweight, read as a credential format when it is partly a
challenge to the whole frame.

The related risk is that the framework becomes accommodating enough to stop making
predictions. "The issuer matters as much as its claims are load-bearing" is true and
close to unfalsifiable. The claims here that predict something are the ones worth
defending: nothing is minted in advance, and Regime A should visibly reduce demand
for agent identity in-session rather than increase it. If those two turn out to be
false, the flexible parts do not save the argument.
