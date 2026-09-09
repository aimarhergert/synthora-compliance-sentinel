# Synthora Compliance Sentinel — a trusted enterprise agent on T3N

Built for the Superteam Earn **T3N Agent Build Challenge** (Sep 2026) with the
[T3 ADK](https://docs.terminal3.io/developers/adk/overview/what-is-adk).

An enterprise counterparty due-diligence agent that runs **inside a T3N TEE**:

1. **Sanctions + crypto screening** — calls the SYNTHORA x402 intelligence API
   (`/v1/sanctions-screen`, `/v1/cryptodd`) from inside the enclave. No PII.
2. **PII-safe deep-audit filing** — the compliance officer's verified email is
   a `{{profile.verified_contacts.email.value}}` marker resolved host-side by
   `http-with-placeholders`; plaintext PII never enters WASM memory.
3. **Immutable compliance briefs** — results are aggregated into a brief stored
   in the tenant KV map `z:<tid>:briefs` and anchored in the T3N ledger via
   `kv-store.set-claims-digest(SHA-256(brief))`, so any receipt holder can
   verify the exact brief bytes offline.

## Why this is "trusted"

- The agent authenticates with its **own DID** (`did:t3n:…`), separate from the
  tenant and the user — a leaked agent key only exposes what was explicitly
  granted.
- The data owner authorizes the agent with a **scoped member delegation**:
  exactly these 3 functions, exactly one egress host
  (`api.hergertsynthora.com`). Anything else fails with `egress_denied`.
- The upstream attribution wallet lives in the `secrets` KV map, readable only
  by this contract inside the enclave — not by the agent, not by the caller.
- HTTP 402 (x402) is a first-class outcome: the contract reports payment terms
  instead of failing, so a paying agent can decide programmatically.
- Every screened decision is anchored in the ledger (claims digest), giving
  auditors an offline-verifiable trail.

## Layout

```
contract/   Rust TEE contract (WASM component, wasm32-wasip2)
app/        TypeScript orchestrator (tenant setup + delegation + invocation)
agent-card.json  ERC-8004 agent card (hosted via `t3n agent host-card`)
docs/       Docs review & bug reports from this build
```

## Build & run

Prereqs: Node ≥ 18, Rust + `wasm32-wasip2` target, and three keys from the
[claim page](https://go.terminal3.io/adk-community) (tenant, agent, user — the
agent needs its own claim so it has its own test credits).

```bash
# 1. Build the TEE contract
cd contract && cargo build --release
# → target/wasm32-wasip2/release/z_synthora_compliance.wasm

# 2. Run the full flow
cd ../app && npm install
export T3N_API_KEY=0x...      # tenant key (claim page)
export AGENT_KEY=0x...        # agent key (separate claim — own credits)
export USER_KEY=0x...         # data owner's key
export SYNTHORA_WALLET=0x...  # Base wallet for upstream X-WALLET attribution
npm run run
```

Optional: `SCREEN_NAME`, `SCREEN_ADDRESS`, `AUDIT_SUBJECT`, `AUDIT_TYPE`.

## Register the agent identity (public, discoverable)

```bash
npm i -g @terminal3/t3n-sdk
export T3N_API_KEY=$AGENT_KEY
export AGENT_DID=$(t3n whoami --env testnet)
# edit agent-card.json: replace did:t3n:REPLACE_WITH_AGENT_DID with $AGENT_DID
t3n agent host-card --file agent-card.json --env testnet
curl https://<node>/api/agent-card/$AGENT_DID   # verify
```

## Maintenance & handover

- **We (SYNTHORA) would prefer to keep running it** — it's a live demo of our
  x402 intelligence API consumed from inside a TEE. Handover is also easy:
  the contract is one crate, the orchestrator one file; a new owner only needs
  to re-run `app/src/run.ts` with their own tenant key (registration creates
  fresh maps/ACLs idempotently) and host the card under their DID.
- Bump `CONTRACT_VERSION` in `contract/Cargo.toml` + `app/src/run.ts` together;
  re-registering allocates a new `contract_id`, so re-create map ACLs with the
  id printed at registration (see `docs/DOCS_FEEDBACK.md` #4).

Docs review and bugs hit during this build: [`docs/DOCS_FEEDBACK.md`](docs/DOCS_FEEDBACK.md).
