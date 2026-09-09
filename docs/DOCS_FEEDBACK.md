# T3N docs review — bugs & rough edges found while building

Reviewed against docs.terminal3.io on 2026-09-09 while building this repo
(Quickstart → Set Up Dev Env → walkthrough → Member Delegation → Register a
Public Agent). Environment: Node v18.19.1, plain Node/tsx (no bundler), Linux.

## Bugs (verifiable)

### 1. `walkthrough/invoke-contract.md` — duplicate import identifier (syntax error)

The "Set up the agent's identity" snippet lists `fetchTrustedManifest` **twice**
in the same import statement:

```ts
import {
  T3nClient, loadWasmComponent, fetchTrustedManifest, createEthAuthInput,
  eth_get_address, metamask_sign, getContractVersion, getNodeUrl,
  fetchTrustedManifest,   // ← duplicate binding: SyntaxError
} from "@terminal3/t3n-sdk";
```

A duplicate binding in one import declaration is a hard `SyntaxError` — the
file cannot run as written.

### 2. `walkthrough/invoke-contract.md` — duplicate `trustAnchor` property (TS1117)

The same page constructs the agent client with `trustAnchor` twice in one
object literal:

```ts
const agentClient = new T3nClient({
  trustAnchor: await fetchTrustedManifest("testnet"),
  wasmComponent,
  trustAnchor,            // ← TS1117: object literal cannot have multiple properties with the same name
  handlers: { EthSign: metamask_sign(agentAddress, undefined, agentKey) },
});
```

The `userClient` snippet below it repeats the same pattern. Under `strict`
TypeScript this is a compile error; in plain JS it silently shadows.

### 3. `member-delegation.md` — `scopes` marked required, but every example omits it

The "What a grant can say" table marks `scopes` as **required: yes**, yet both
the raw `member-delegation-update` example and the `updateMemberDelegation`
example pass grants **without** `scopes`. The SDK confirms the table, not the
examples: copying the doc example verbatim fails typechecking against
`@terminal3/t3n-sdk@5.2.0`:

```text
error TS2345: Argument of type '{ grantee: string; contract_id: string;
version_req: string; functions: string[]; allowed_hosts: string[]; }' is not
assignable to parameter of type 'BoundGrant'.
  Property 'scopes' is missing ... but required in type 'BoundGrant'.
```

So the examples as written do not compile. Please add `scopes` to the examples
(`scopes: []` works for function+egress-only grants like ours).

## Rough edges (feedback, not bugs)

### 4. No API to recover a tail's `contract_id` after re-registration

`register-contract.md` warns about this itself. We hit the design constraint
while scripting redeploys: the only `contract_id` source is the register
response, so automation must persist it or map ACLs go stale. A read-only
`contracts.list` / `contracts.get(tail)` on `TenantClient` would make
redeploys idempotent.

### 5. Multi-agent onboarding needs N interactive SSO claims

Quickstart + Register a Public Agent + Member Delegation together require
**three** separately-claimed keys (tenant, agent, user), each via an
interactive Google SSO on the claim page, each shown exactly once. That's fine
for a human tutorial but painful for scripted/agentic setups. A CLI
(`t3n keygen` + testnet faucet, or tenant→agent credit transfer) would help;
noting the docs already say there is no `t3n keygen`.

### 6. WASM/bundler warning is accurate — plain Node works

We heeded the Next.js/Vite/WASM warning and ran everything from a plain
Node + tsx script: `loadWasmComponent()` worked first try on Node 18.19.1.
Suggest also mentioning `tsx` explicitly in the quickstart (it's already the
runner used) as the known-good path. (npm prints an `EBADENGINE` warning for
`@terminal3/t3n-sdk` on Node 18 — worth stating the supported Node range in
the quickstart prerequisites.)

### 7. `cargo test` in the contract crate tries to execute the WASM binary

The reference crate's `.cargo/config.toml` pins `build.target =
wasm32-wasip2`, so `cargo test` builds the test binary as WASM and then fails
to run it (`Permission denied (os error 13)` on Linux — there is no wasm
runner configured). Workaround: `cargo test --target x86_64-unknown-linux-gnu`.
Worth one line in set-up-dev-env or the reference README, since the crate
ships unit tests readers will naturally try to run.

## What worked well

- `TenantClient` sub-namespaces note (`tenant.tenant.me()`) saved real time.
- `readers: { only: [...] }` REQUIRED callout in create-kv-maps is exactly the
  kind of default-deny trap that's good to flag — it caught us too.
- `updateMemberDelegation` read-merge-write helper is the right default; the
  raw `member-delegation-update` foot-gun is well flagged.
