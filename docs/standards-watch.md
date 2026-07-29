# Standards watch

> Track, don't conform — yet. The agent-identity standards are converging but
> pre-consensus (drafts at `-00`…`-07` as of June 2026). The job of this file is
> to (1) record where the field is splitting, (2) map our endpoints to the drafts
> so alignment is checkable each revision, and (3) say honestly what conforming
> would cost when a lane stabilizes. See [thesis.md](thesis.md) for *why* and
> [scope-and-boundaries.md](scope-and-boundaries.md) for the issuer/consumer line
> that makes conformance cheap.

## The bifurcation (and which side we're on)

The standards are splitting along exactly the line this repo draws — human-wallet
vs. agent/workload-direct:

| | human-wallet branch | **agent / workload-direct branch (us)** |
|---|---|---|
| Presentation | OID4VP — verifier-initiated, wallet round-trip, human consent | present-directly (sign a VP) **or** resolve-by-lookup |
| Examples | OID4VP, EUDI, OID4VC-HAIP, PingOne Credentials, OpenCred, walt.id verifier | WIMSE, SPIFFE, A2A portable creds, the IETF agent-auth drafts |
| Why | humans can't hold keys → wallet mediates consent | agents hold keys → no wallet, no consent step |

We are wholly in the right column. The left column is the "useless for agents"
verification model (see the OpenCred/Neo discussion): correct for humans, wrong
shape for agents.

## What to track, by our two verification shapes

**Policy-model / by-lookup (our `/resolve`, `/attributes`)**
- **WIMSE** — IETF WG (chartered 2024), the most standards-mature. Workloads
  present JWT/X.509 creds, verified against per-trust-domain authorized issuers +
  trust anchors distributed out-of-band — *our federation/trusted-issuer model,
  verbatim.* Wallet-less by construction. `draft-ietf-wimse-arch-07`; arch → RFC
  ~2026–27, full stack 2027–28. **Primary anchor for `/resolve`.**
  <https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/> ·
  <https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/>
- **SPIFFE/SPIRE** — the deployed reference WIMSE is partly standardizing
  (mTLS / JWT-SVID, verify against trust bundle).
- **transaction-tokens-for-agents** (IETF OAuth) — `actor`/`principal` token
  propagation; complements `/resolve` on the delegated-token path.

**Credential-model / presentation (our `/verify`)**
- **A2A** (Linux Foundation) — states our `/verify` almost verbatim: *"a portable
  credential is a signed attestation an agent can present to any counterparty and
  have verified — without the recipient querying the issuing platform."* Offline,
  no callback, no wallet. **Caveat / our opening:** A2A *delegates credential
  management entirely to implementers* (impersonation, card tampering, replay are
  named risks) — i.e. it under-specifies the verification rigor our `/verify`
  implements (two-sig + status + nonce). Track as alignment *and* possible
  contribution. <https://zylos.ai/research/2026-03-26-agent-interoperability-protocols-mcp-a2a-acp-convergence/>
- **DIDComm / DIF presentation proof** — the agent-to-agent exchange envelope A2A
  leans on.

**Framing / synthesis (closest to our whole thesis)**
- **AIP — `draft-aip-agent-identity-protocol`** — opens with our exact argument:
  *"AI agents are deployed with the same credentials as humans… nothing in the
  request distinguishes an agent's tool call from a direct human action."* Spans
  MCP + A2A with policy enforcement. **Closest framing-match; a live venue to
  engage.** <https://www.ietf.org/archive/id/draft-aip-agent-identity-protocol-00.html>
- **ACAP — `draft-yakung-oauth-agent-attestation`** — short-lived signed JWT with
  *scope-limited permissions* = our charter-as-scoped-credential.
  <https://datatracker.ietf.org/doc/draft-yakung-oauth-agent-attestation/>
- **`draft-klrc-aiagent-auth`** — context-gathering provisioning → short-lived
  creds = our voucher enrollment + attestation.
  <https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/>
- **`draft-yl-agent-id-requirements`** — requirements framing; watch for WG
  consensus direction.

## DID method: `did:web` now, `did:webvh` as the identified upgrade

A separate axis from credential format, and the one place where our choice has a
known structural gap rather than a cosmetic one.

**Why `did:web` is right today.** Resolution is an HTTPS GET, so every verifier can
do it with no library and no new trust root. ATProto resolves it natively, which the
Watershed PDS needs and which most alternatives fail immediately. It gives
revocation somewhere to publish and an identifier that survives key rotation —
`POST /agents/{id}/rotate` exists because of it. `did:key` is fully self-rooted but
breaks continuity on every rotation and has nowhere to put status, which trades a
real capability set for a property that key-pinning delivers more cheaply.

**The gap.** `did:web` has no cryptographic continuity between DID document
versions. Whoever serves the document declares which key controls the DID, so the
key can be substituted and a verifier resolving fresh cannot tell substitution from
legitimate rotation. Our rotate endpoint demands a self-proof, but that is an
application-level control the registry chooses to enforce — database or domain
access goes around it. **The guarantee is operational, not cryptographic.**

**Mitigation today (consumption-side, and load-bearing).** Verifiers pin the key at
first contact and treat a key change as an event to notice rather than follow. See
[thesis.md](thesis.md#verifiers-should-pin-the-key-not-the-did) — every anti-capture
claim this project makes depends on it, and no issuer-side change substitutes for it.

**The upgrade.** `did:webvh` (DID Web + Verifiable History, formerly `did:tdw`)
extends `did:web` with an append-only log in which each DID document version is
signed and authorized by the preceding key, plus a self-certifying identifier and
provable continuity across a domain move. That closes the substitution hole
structurally, and makes the registry-portability story in thesis.md real rather than
dependent on services agreeing to link two DIDs.

**Cost:** resolver support, which is the whole problem. Far less deployed than
`did:web`, and a stock ATProto PDS will not resolve it — adopting it means carrying
support on our own PDS and waiting on everyone else. Check current adoption before
committing; this file's reading is mid-2026 and DID-method uptake moves.

**Revisit when:** ATProto (or another consumer we own) can resolve `did:webvh`, or a
consumer needs registry-independence it can verify rather than take on trust.

## Endpoint ↔ draft correspondence

| This repo | Conforms toward |
|---|---|
| `/charter` (ldp_vc / jwt_vc / sd_jwt_vc) | A2A portable W3C VC · ACAP scoped-perm JWT · WIMSE workload-cred profile |
| `/resolve`, `/agents/{id}/attributes` | WIMSE workload-cred verification · transaction-tokens-for-agents |
| `/verify` | A2A portable-credential present-and-verify · DIF presentation proof |
| operator voucher enrollment | `draft-klrc-aiagent-auth` provisioning · WIMSE issuance |
| `/.well-known/did.json` (trust anchor) | WIMSE trust-domain anchors |
| `/agents/{id}/did.json` (DID method) | `did:web` today · `did:webvh` is the upgrade — see above |
| `/status/list` (revocation) | **divergent** — see below |

## What conforming costs: mostly JSON, one behavioral exception, no rearchitecture

Because we are an *issuer* with a clean consumer boundary, conformance is
localized to the issuance producers (`app/vc.py`, `app/jwt_vc.py`) and is mostly
the *shape of what we emit*:

- **Pure JSON (easy):** claim names, `@context`, `vct`, the scoped-permission
  structure, the `credentialStatus`/status entry shape. Edit the producers; no new
  behavior. The producers are centralized precisely so this stays a templating
  change.
- **Small targeted code:** the signature envelope. ✅ *Done* — `ldp_vc` now uses
  multibase `z`/base58btc (per the W3C suite) and folds the document `@context`
  into the proofConfig before hashing, so the proof is eddsa-jcs-2022-shaped and
  independently verifiable (see `test_ldp_vc_proof_is_spec_shaped`). Remaining
  caveat: `jcs()` is a simplified canonicalizer — byte-identical to RFC 8785 for
  our string/array payloads (no floats) but not a certified RFC 8785 lib; swap in
  a full one only if a strict external verifier requires it. (Adopting
  VC-JOSE-COSE or a specific JWT `typ` profile, if a draft mandates one, is
  similarly localized.)
- **The one genuinely behavioral exception — credential lifetime model.** The
  agent drafts (ACAP "short-lived JWT", klrc "short-lived credentials") lean on
  **short-lived, frequently-reissued** creds *instead of* a revocation list. We do
  the opposite: long-lived charter (`CHARTER_TTL_DAYS`, default 90) + a Bitstring
  Status List. Matching the short-lived direction is config + a re-issuance
  cadence, not JSON — a real design choice to make when a lane stabilizes. (Our
  model is also valid; this is a philosophy fork to watch, not a bug.)
- **Not our code (consumer-side):** the presentation/exchange protocol itself
  (A2A Agent Cards, DIF presentation, OID4VP, token exchange) and the PDP. Per the
  boundary, those live in the consumer — so protocol conformance never touches
  this repo.

**Verdict:** ~80% JSON in the issuance producers, ~20% small localized code (mainly
the envelope + the lifetime decision), **0% architectural.** The boundary work is
what makes this true — issuance is the only conformance surface here.

## When to revisit

Don't conform now — chasing `-00` drafts means re-chasing them every revision.
Keep the producers flexible (they are) and revisit when:
- **WIMSE arch → RFC** (the most likely first hard target; aligns `/resolve`), or
- **AIP / ACAP reach `-02`+ with WG adoption** (aligns the charter + framing), or
- **`did:webvh` becomes resolvable by a consumer we own** (closes the key-substitution
  gap structurally instead of by consumption discipline), or
- a consumer you own (P1AZ, an A2A peer) needs a specific profile to interop.

The `eddsa-jcs-2022` envelope deviation (multibase `u`→`z` + proofConfig
`@context`) is already fixed, so `ldp_vc` is structurally standards-verifiable
today; the next conformance steps are format/lifetime choices that wait on a draft
picking a lane.
