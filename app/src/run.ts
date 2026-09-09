/**
 * run.ts — end-to-end orchestrator for the z-synthora-compliance TEE contract.
 *
 * Follows the T3N ADK docs flow exactly:
 *   Quickstart (auth) → Set Up Dev Env (TenantClient) → Register contract →
 *   Create KV maps + seed secrets → Agent session → Member delegation → Invoke.
 *
 * Required env (see README):
 *   T3N_API_KEY      tenant key from the claim page
 *   AGENT_KEY        separate key for the agent (its own claim, own credits)
 *   USER_KEY         key standing in for the data owner (user)
 *   SYNTHORA_WALLET  0x... Base wallet used as X-WALLET attribution upstream
 *
 * Optional env:
 *   SCREEN_NAME      name to sanctions-screen     (default: "John Smith")
 *   SCREEN_ADDRESS   EVM address to due-diligence (default: none)
 *   AUDIT_SUBJECT    deep-audit subject           (default: SCREEN_NAME)
 *   AUDIT_TYPE       person|company|domain|username (default: "company")
 */
import { readFile } from "fs/promises";
import {
  T3nClient,
  TenantClient,
  setEnvironment,
  loadWasmComponent,
  eth_get_address,
  metamask_sign,
  createEthAuthInput,
  fetchTrustedManifest,
  getContractVersion,
  getNodeUrl,
} from "@terminal3/t3n-sdk";

setEnvironment("testnet");

const WASM_PATH = new URL(
  "../../contract/target/wasm32-wasip2/release/z_synthora_compliance.wasm",
  import.meta.url,
);
const CONTRACT_TAIL = "synthora-compliance";
const CONTRACT_VERSION = "0.1.0";
const ALLOWED_HOSTS = ["api.hergertsynthora.com"];
const FUNCTIONS = ["screen-counterparty", "request-deep-audit", "compile-brief"];

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name} — see README.md`);
  return v;
}

async function authenticate(key: string, label: string) {
  // SDK 5.14.0 trust bootstrap is broken on testnet today (verified live
  // 2026-09-09, https://cn-api.sg.testnet.t3n.terminal3.io/api/trust-manifest):
  // the node serves a manifest WITHOUT rtmr1_allowlist, so
  //   1. fetchTrustedManifest("testnet") rejects it as "malformed"
  //      (SignedTrustManifest.rtmr1_allowlist is required in 5.14.0), and
  //   2. projecting it via manifestToTrustAnchor yields an anchor T3nClient
  //      refuses ("must be ... { expected_peer_ids, rtmr3_allowlist,
  //      rtmr1_allowlist }" — RTMR1 must be non-empty and is unpublished).
  // Until the operator republishes the manifest with rtmr1_allowlist, the
  // only way to run against testnet is the SDK's explicit opt-out below.
  // DEMO ONLY — disables DKG attestation verification. See docs/DOCS_FEEDBACK.md.
  let trustAnchor;
  try {
    trustAnchor = await fetchTrustedManifest("testnet");
  } catch (e) {
    console.warn(
      `[${label}] WARNING: ${(e as Error).message} ` +
        `Falling back to { unsafe_trust_server: true } for this demo run ` +
        `(testnet manifest infra bug — attestation verification OFF).`,
    );
    trustAnchor = { unsafe_trust_server: true as const };
  }
  const wasmComponent = await loadWasmComponent();
  const address = eth_get_address(key);
  const client = new T3nClient({
    trustAnchor,
    wasmComponent,
    handlers: { EthSign: metamask_sign(address, undefined, key) },
  });
  await client.handshake();
  const did = await client.authenticate(createEthAuthInput(address));
  console.log(`[${label}] authenticated as ${did.value}`);
  return { client, did: did.value as string };
}

// ── 1. Tenant session (Quickstart) ──────────────────────────────────────────
const tenantKey = need("T3N_API_KEY");
const { client: t3n, did: tenantDid } = await authenticate(tenantKey, "tenant");

// ── 2. TenantClient (Set Up Dev Env) ────────────────────────────────────────
const tenant = new TenantClient({ t3n, baseUrl: getNodeUrl(), tenantDid });
await tenant.tenant.me();
console.log("[tenant] TenantClient ready.");

// ── 3. Register the WASM contract ───────────────────────────────────────────
const wasmBytes = await readFile(WASM_PATH);
const { contract_id: contractId } = await tenant.contracts.register({
  tail: CONTRACT_TAIL,
  version: CONTRACT_VERSION,
  wasm: wasmBytes,
});
const tenantId = tenantDid.slice("did:t3n:".length);
const TENANT_CONTRACT = `z:${tenantId}:${CONTRACT_TAIL}`;
console.log(`[tenant] registered ${TENANT_CONTRACT} as contract id ${contractId}`);

// ── 4. KV maps + seed the upstream wallet into secrets ─────────────────────
for (const tail of ["secrets", "briefs"]) {
  await tenant.maps
    .create({
      tail,
      visibility: "private",
      writers: { only: [contractId] },
      readers: { only: [contractId] }, // REQUIRED — kv-governor defaults to deny
    })
    .catch((e: Error) => {
      if (!/already exists/i.test(e.message)) throw e; // MapAlreadyExists is idempotent
      console.log(`[tenant] map ${tail} already exists, reusing`);
    });
}
await tenant.executeControl("map-entry-set", {
  map_name: tenant.canonicalName("secrets"),
  key: "synthora_wallet",
  value: need("SYNTHORA_WALLET"),
});
console.log("[tenant] synthora_wallet sealed in z:<tid>:secrets");

// ── 5. Agent session — separate key, separate DID, separate credits ────────
const { did: agentDid } = await authenticate(need("AGENT_KEY"), "agent");

// ── 6. User (data owner) grants the agent scoped access ────────────────────
const { client: userClient, did: userDid } = await authenticate(need("USER_KEY"), "user");
const contractVersion = await getContractVersion(getNodeUrl(), TENANT_CONTRACT);
// updateMemberDelegation read-merge-writes, so other grants survive.
await userClient.updateMemberDelegation({
  grantee: agentDid,
  contract_id: TENANT_CONTRACT,
  version_req: contractVersion,
  functions: FUNCTIONS,
  scopes: [], // no user data scopes — this contract only calls functions + egress hosts
  allowed_hosts: ALLOWED_HOSTS,
});
console.log(`[user ${userDid}] granted ${agentDid} → ${TENANT_CONTRACT} ${FUNCTIONS.join(",")}`);

// ── 7. Agent invokes the contract ───────────────────────────────────────────
const { client: agentClient } = await authenticate(need("AGENT_KEY"), "agent");
const call = (function_name: string, input: unknown) =>
  agentClient.executeAndDecode({
    contract_id: TENANT_CONTRACT,
    contract_version: contractVersion,
    function_name,
    input,
  });

const screenInput: Record<string, string> = {
  name: process.env.SCREEN_NAME ?? "John Smith",
};
if (process.env.SCREEN_ADDRESS) screenInput.address = process.env.SCREEN_ADDRESS;

const screening = await call("screen-counterparty", screenInput);
console.log("[agent] screen-counterparty →", JSON.stringify(screening, null, 2));

const audit = await call("request-deep-audit", {
  subject: process.env.AUDIT_SUBJECT ?? screenInput.name,
  type: process.env.AUDIT_TYPE ?? "company",
});
console.log("[agent] request-deep-audit →", JSON.stringify(audit, null, 2));

const brief = await call("compile-brief", {
  counterparty: process.env.AUDIT_SUBJECT ?? screenInput.name,
  screening,
  deep_audit: audit,
});
console.log("[agent] compile-brief →", JSON.stringify(brief, null, 2));

console.log(
  "Done. Brief is stored in z:<tid>:briefs and anchored via claims digest:",
  (brief as { claims_digest?: string }).claims_digest,
);
