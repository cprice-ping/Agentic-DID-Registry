# Charter mapping — how this repo's charter projects onto the wire

> Concrete integration note (not the *why* — that's [thesis.md](thesis.md)). Maps
> the standing **charter** this repo issues onto (1) the **Transaction Token for
> Agents** edge you already run in Notflux, and (2) the **Open Agent Passport /
> AGNTCY** at-rest format, so the charter is portable at rest and projected
> correctly in flight.
>
> Claim-name caveat: the base Txn-Token claims (`sub`, `act`, `tid`, `purp`,
> `azd`, `rctx`) and the RFC 8693 `act` actor claim are stable and already present
> in Notflux tokens. The **agent-draft-specific** field names
> (`draft-oauth-transaction-tokens-for-agents`) should be confirmed against the
> exact version you deploy — IETF mirrors were unreachable when this was written.

## The frame: standing vs. per-request

- **Charter = standing.** Durable, issuer-signed, about the agent's identity;
  carries `can` (affordances) + intent + provenance. Issued once, on need.
- **Transaction token = per-request projection.** Ephemeral, minted per call,
  carries actor/principal + purpose + authorization-details through the chain.

The charter does **not** replace the token. It **feeds and bounds** it. The token
carries *who is acting for whom, doing what, now*; the charter supplies the
standing *what-this-agent-is-allowed* ceiling that the token model itself leaves
unspecified. That gap — the Txn-Token carries `azd` but is agnostic about where
`azd`'s bound comes from — is exactly what an issuer-signed charter fills cleanly.

## Mapping: charter → Transaction Token for Agents

| Charter (standing) | Txn-Token (per-request) | Relationship |
|---|---|---|
| subject **DID** (self-owned identity) | `act.sub` (carrying, or resolvable to, the agent DID) | **identifier → identity**: `act.sub` must point at / resolve to the charter DID. Carry the DID in `act` directly, or have the PIP resolve `act.sub` → charter DID. |
| vouched-by / on-behalf-of | `sub` (principal) + `act` (actor) chain | charter sets the *standing* delegation; token carries the *live* one. Personal agent: `sub`=person, `act.sub`=agent DID. |
| `capabilities` (`can`, the **ceiling**) | `azd` (authorization-details, the **slice**) | **`azd ⊆ charter.capabilities`** — attenuation. The charter is the independent ceiling over what `azd` may contain. |
| `intent` (standing purpose) | `purp` (transaction purpose) | per-request `purp` must be consistent with charter `intent` (purpose-binding). |
| issuer signature (**provenance**) | TTS signature (domain-local trust) | charter provenance is what *justifies admitting/elevating* the actor into the domain's token flow. Portable trust → local trust. |
| — (environment is **not** identity) | `rctx` (requester context) | the operating environment lands in `rctx`, per "environment is a claim, not the identity." Stays out of the charter. |
| charter id / DID (audit) | `tid` (transaction id) | charter referenced in the audit/correlation record. |

The three concerns stay cleanly separated end-to-end: **identity** = `act.sub` →
charter DID; **affordance** = `azd ⊆ charter.can`; **environment** = `rctx`.

### Store-safe encodings are not an identity layer (e.g. SpiceDB `sub_hash`)

SpiceDB object ids can't contain colons, and colons are exactly what DIDs and OIDC
subs are made of — so Notflux hashes `act.sub` into a colon-free `sub_hash`. That
is a **store-local encoding of the identifier**, not a layer of identity: it sits
*below* the identifier (identity → identifier → store encoding), is computed
deterministically at the SpiceDB edge, and **need not travel in the token at all**.
Propagating it as a token claim leaks one store's lexical constraint into the wire
format — the boundary anti-pattern, at the storage layer. Keep it contained at the
consumer; SpiceDB recomputes it from `act.sub` when it writes a tuple. (A
*reversible* encoding avoids the lossy hash and the need to stash the raw id
separately for audit, but that's a SpiceDB-edge detail, not a wire concern.)

## Where the charter enters the token lifecycle

```
1. Agent holds charter (DID + capabilities, issuer-signed)        ← this repo
2. Agent initiates a call → DaVinci RFC 8693 exchange (the TTS)
3. AT EXCHANGE TIME the TTS resolves the charter (via the Registry PIP, by
   act.sub → charter DID) and:
     • binds act to the agent identity (= charter subject)
     • clamps azd to  charter.capabilities ∩ requested
     • sets purp consistent with charter.intent
   → the token is BORN bounded by the charter
4. Token flows the chain; at the RS, P1AZ evaluates
     permit = azd ⊆ policy(sub, act, purp, rctx)
   (defense-in-depth: P1AZ MAY re-check azd ⊆ charter via the PIP)
```

Two insertion points; either or both:
- **Exchange-time clamp** (preferred): the DaVinci TTS consults the charter and
  clamps `azd`, so every downstream hop inherits a charter-bounded token.
- **Decision-time re-check**: P1AZ re-verifies `azd ⊆ charter.can` via the PIP —
  the independent ceiling over whatever the exchange (or a looser grant path) did.

This is `allowed = grant ∩ charter ∩ policy` from the design notes, expressed in
Txn-Token terms as `azd ⊆ charter.can`, enforced where the chain is minted.

## Mapping: charter → Open Agent Passport / AGNTCY (at rest)

To make the charter portable across substrates, emit it in OAP/AGNTCY-compatible
shape rather than a bespoke schema. The substance is already identical:

| This repo's charter | OAP / AGNTCY |
|---|---|
| `credentialSubject.id` (agent DID) | DID-based agent identity |
| `capabilities` / `can` | "declarative capabilities and limits" |
| `issuer` + Data Integrity / JWS proof | "signed by the issuer," verifiable by any conforming impl |
| `intent` | purpose / description |
| `ldp_vc` / `jwt_vc` / `sd_jwt_vc` outputs | the passport VC document |

So the three serializations line up: **OAP/AGNTCY = the portable at-rest format**;
**Txn-Token = the in-flight projection at the Notflux edge**; the **charter = the
single source** both derive from. Adopt OAP's field names where they exist; keep
this repo as the issuer that emits them.

## What stays out (per the boundary)

This doc describes how *consumers* project the charter. The projection logic —
the DaVinci clamp flow, the P1AZ policy, the PIP resolver — lives in the consuming
repos, not here. This repo issues the charter and serves DID documents; it does
not mint Txn-Tokens, run the exchange, or make the decision. See
[scope-and-boundaries.md](scope-and-boundaries.md).
