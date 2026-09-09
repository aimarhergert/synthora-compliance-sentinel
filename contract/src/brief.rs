//! compile_brief: aggregates screening and deep-audit results into an
//! immutable compliance brief. The brief is written to the tenant KV map
//! `z:<tid>:briefs` and its SHA-256 is set as the transaction claims digest,
//! so the brief is anchored in the Raft ledger's Merkle leaf — any holder of
//! the call receipt can verify the exact brief bytes offline.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(serde::Deserialize)]
pub struct CompileBriefReq {
    /// Human label for the counterparty (used in the brief key and title).
    pub counterparty: String,
    /// Output of screen-counterparty (any JSON).
    pub screening: serde_json::Value,
    /// Optional output of request-deep-audit (any JSON).
    pub deep_audit: Option<serde_json::Value>,
}

pub fn compile_brief(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: CompileBriefReq =
        serde_json::from_slice(input).map_err(|e| format!("compile-brief: bad input: {e}"))?;

    if req.counterparty.trim().is_empty() {
        return Err("compile-brief: `counterparty` must not be empty".to_string());
    }

    #[cfg(target_arch = "wasm32")]
    {
        let resp = compile_wasm(req)?;
        serde_json::to_vec(&resp).map_err(|e| e.to_string())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = req;
        Err("compile_brief is only implemented on the wasm32 target".to_string())
    }
}

#[cfg(target_arch = "wasm32")]
use crate::host::{
    interfaces::{kv_store, logging},
    tenant::tenant_context,
};

#[cfg(target_arch = "wasm32")]
fn compile_wasm(req: CompileBriefReq) -> Result<serde_json::Value, String> {
    use sha2::Digest;

    let tid = tenant_context::tenant_did();
    let seq = tenant_context::seq_no();
    let ts = tenant_context::cluster_timestamp_secs();

    // Deterministic per-tx id: sequence number is unique per committed tx.
    let brief_id = format!("brief-{seq:016x}");
    let map_name = format!("z:{}:briefs", hex::encode(&tid));

    let brief = serde_json::json!({
        "brief_id": brief_id,
        "contract_version": crate::CONTRACT_VERSION,
        "counterparty": req.counterparty,
        "cluster_timestamp_secs": ts,
        "seq_no": seq,
        "screening": req.screening,
        "deep_audit": req.deep_audit,
    });
    let brief_bytes = serde_json::to_vec(&brief).map_err(|e| e.to_string())?;

    kv_store::put(&map_name, brief_id.as_bytes(), &brief_bytes)
        .map_err(|e| format!("briefs map write failed (map z:<tid>:briefs must exist): {e}"))?;

    // Anchor the exact brief bytes in the tx Merkle leaf.
    let digest: [u8; 32] = sha2::Sha256::digest(&brief_bytes).into();
    kv_store::set_claims_digest(&digest)
        .map_err(|e| format!("set-claims-digest failed: {e}"))?;

    let _ = logging::info(&format!(
        "brief {brief_id} stored and anchored ({} bytes)",
        brief_bytes.len()
    ));

    Ok(serde_json::json!({
        "brief_id": brief_id,
        "map": map_name,
        "claims_digest": hex::encode(digest),
        "seq_no": seq,
    }))
}
