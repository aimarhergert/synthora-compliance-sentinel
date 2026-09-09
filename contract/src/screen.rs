//! screen_counterparty: sanctions + crypto due-diligence via the SYNTHORA
//! x402 intelligence API. Carries no PII — names and addresses are business
//! identifiers, and the caller's attribution wallet is read from the tenant
//! `secrets` map, never passed as an argument.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(serde::Deserialize)]
pub struct ScreenReq {
    /// Legal / trade name for sanctions screening (OFAC SDN + UN + OpenSanctions).
    pub name: Option<String>,
    /// EVM address for crypto due-diligence (honeypot / sanctions / reputation).
    pub address: Option<String>,
}

const SYNTHORA_BASE: &str = "https://api.hergertsynthora.com";
/// Never hold more than this from an upstream leg inside WASM — a misbehaving
/// or misconfigured upstream must not OOM the enclave.
const MAX_LEG_BYTES: usize = 65_536;

/// Entry point called from `lib.rs`. `input` is the raw JSON bytes from the
/// node's `generic-input.input` field.
pub fn screen_counterparty(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: ScreenReq =
        serde_json::from_slice(input).map_err(|e| format!("screen-counterparty: bad input: {e}"))?;

    if req.name.is_none() && req.address.is_none() {
        return Err("screen-counterparty: provide at least one of `name` or `address`".to_string());
    }

    #[cfg(target_arch = "wasm32")]
    {
        let resp = screen_wasm(req)?;
        serde_json::to_vec(&resp).map_err(|e| e.to_string())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = req;
        Err("screen_counterparty is only implemented on the wasm32 target".to_string())
    }
}

#[cfg(target_arch = "wasm32")]
use crate::host::{
    interfaces::{http as http_iface, kv_store, logging},
    tenant::tenant_context,
};

/// Read the caller's X-WALLET attribution header from `z:<tid>:secrets`.
/// Missing wallet is NOT an error: the upstream free tier also allows a small
/// number of unattributed calls per day.
#[cfg(target_arch = "wasm32")]
fn get_wallet() -> Option<String> {
    let tid = tenant_context::tenant_did();
    let map_name = format!("z:{}:secrets", hex::encode(&tid));
    kv_store::get(&map_name, b"synthora_wallet")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
}

/// POST a JSON body to one SYNTHORA leg and classify the result.
/// HTTP 402 is a first-class outcome (`payment_required`) — the x402 terms in
/// the body tell the calling agent exactly what paying would cost.
#[cfg(target_arch = "wasm32")]
fn call_leg(path: &str, wallet: Option<&str>, body: &serde_json::Value) -> serde_json::Value {
    let mut headers: Vec<(String, String)> = alloc::vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("accept".to_string(), "application/json".to_string()),
    ];
    if let Some(w) = wallet {
        headers.push(("x-wallet".to_string(), w.to_string()));
    }

    let payload = match serde_json::to_vec(body) {
        Ok(p) => p,
        Err(e) => return serde_json::json!({ "status": "encode_error", "detail": e.to_string() }),
    };

    let resp = match http_iface::call(&http_iface::Request {
        method: http_iface::Verb::Post,
        url: format!("{SYNTHORA_BASE}{path}"),
        headers: Some(headers),
        payload: Some(payload),
    }) {
        Ok(r) => r,
        Err(e) => return serde_json::json!({ "status": "transport_error", "detail": e }),
    };

    if resp.payload.len() > MAX_LEG_BYTES {
        return serde_json::json!({
            "status": "http_error",
            "code": resp.code,
            "detail": format!("upstream response too large ({} bytes)", resp.payload.len()),
        });
    }
    let text = String::from_utf8_lossy(&resp.payload).to_string();

    match resp.code {
        200 => serde_json::json!({
            "status": "ok",
            "result": serde_json::from_str::<serde_json::Value>(&text)
                .unwrap_or(serde_json::Value::String(text)),
        }),
        402 => serde_json::json!({
            "status": "payment_required",
            "code": 402,
            "x402_terms": serde_json::from_str::<serde_json::Value>(&text)
                .unwrap_or(serde_json::Value::String(text)),
        }),
        code => serde_json::json!({
            "status": "http_error",
            "code": code,
            "body": text.chars().take(512).collect::<String>(),
        }),
    }
}

#[cfg(target_arch = "wasm32")]
fn screen_wasm(req: ScreenReq) -> Result<serde_json::Value, String> {
    let wallet = get_wallet();
    let mut out = serde_json::json!({ "seq_no": tenant_context::seq_no() });

    if let Some(name) = req.name {
        let _ = logging::info(&format!("screening name against sanctions lists"));
        out["sanctions"] = call_leg(
            "/v1/sanctions-screen",
            wallet.as_deref(),
            &serde_json::json!({ "name": name }),
        );
    }
    if let Some(address) = req.address {
        let _ = logging::info(&format!("running crypto due-diligence leg"));
        out["crypto_dd"] = call_leg(
            "/v1/cryptodd",
            wallet.as_deref(),
            &serde_json::json!({ "address": address }),
        );
    }
    Ok(out)
}
