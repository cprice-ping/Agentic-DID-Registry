# Scope & boundaries

This document exists because the pull to make this repo do more is *structural*,
not a lapse of discipline. Writing the boundary down won't stop you reaching
across it — but it will make you notice the moment you do.

## The one-line scope

**This repo is an issuer.** Charter out, operator voucher in, pattern-agnostic.
It issues `who` (a DID-bound identity) and `can` (a signed charter of affordances
+ intent + provenance). It never decides `allowed`.

## The distinction that keeps getting conflated

"Agentic identity/authorization" is not one problem. It is at least two, and they
differ on every axis that matters:

| | credential-model | policy-model |
|---|---|---|
| Example | Agentic-Watershed | PingOne Authorize + SpiceDB |
| Trust | peer-to-peer, decided by the consumer offline | centralized, decided by a PDP at the gate |
| Agent acts | on its own behalf | on behalf of a human (`sub` / `act` delegation) |
| Authority | travels with the credential (capability) | computed at the gate (policy) |
| Identity | portable DID | thin positional id (e.g. `sub_hash` from a token chain) |
| Verifier | a peer agent (the subscriber) | an enterprise PDP |
| The question | "should I believe this data?" | "may this action proceed?" |
| The charter is | a *presented capability* | a *PIP attribute* |

These are different problems — provenance/trust vs. access control, a credential
model vs. a policy model. There is no single charter-*consumption* design that
serves both. Trying to build one is the failure mode.

## What is shared vs. what is not

- **Issuance is shared.** Both patterns need the same front end: a deliberate,
  out-of-band-rooted process that mints "this agent is X, chartered for Y, vouched
  by Z" as a verifiable artifact. That is this repo. One issuer.
- **Consumption is pattern-specific.** The credential-model consumes the charter
  as a presented capability (offline, two signatures, no PDP). The policy-model
  consumes it as an attribute resolved into a PDP and intersected with the local
  grant + policy. Same charter, different verification topology — because the
  *trust* topology differs. N consumers, one adapter per verifier you own.

The architecture, then: **one issuance kernel; a thin consumption adapter per
owned verifier; no grand unified theory.**

## Calibration — is the charter even load-bearing?

Honesty matters more than reach. The charter earns its place differently per
pattern:

- **credential-model: needed.** The substrate (e.g. ATProto) gives identity, not
  authorization. The charter is the *only* mechanism a peer verifier has to decide
  trust. Load-bearing.
- **policy-model: optional.** A PDP (SpiceDB + ABAC) may already decide `allowed`.
  The charter earns its keep there only as (a) an independent *ceiling* over
  grants written by a looser path (e.g. an LLM governor) — issued by the deliberate
  operator-voucher flow, a different key than the grant path, so
  `allowed = grant ∩ charter ∩ policy`; (b) *provenance* the grant graph can't
  express; or (c) *portability* across trust domains. If none of those apply,
  the charter is redundant there — and that is an acceptable answer.

## The rule

> The moment this repo imports knowledge of a consumer's substrate — SpiceDB,
> ATProto, Kong, a PIP schema, an OAuth token shape — the boundary is broken.
> That coupling belongs in the consuming repo. This repo issues a charter and
> serves DID documents; everything about *how a charter is consumed* lives where
> the verifier lives.

## Things that look like they belong here but don't

- **A token broker** (charter → OAuth). Consumption. Belongs to the policy-model
  consumer, and only if that consumer's verifiers speak OAuth.
- **An OID4VP holder** (driving Neo presentation sessions). Consumption.
- **A PDP / policy / allow-deny.** Consumption.
- **`present()` / `verify_presentation()`** in `registry_client.py` — a *reference
  consumer* for the credential-model, kept for the demo and tests. Consumption
  wearing an issuer's clothes; its canonical home is the consuming agent.

If a proposed change makes this repo smarter about *deciding* or *presenting*
rather than *issuing*, it is on the wrong side of the line.
