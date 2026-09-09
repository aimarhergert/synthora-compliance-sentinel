//! request_deep_audit: files a deep OSINT audit for a counterparty via
//! `http-with-placeholders`. The compliance officer's verified email rides in
//! the request body as `{{profile.verified_contacts.email.value}}` and is
//! substituted by the host at dispatch time — plaintext PII never enters
//! WASM memory, and a compromised contract reading the body back would see
//! only the unresolved template.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(serde::Deserialize)]
pub struct DeepAuditReq {
    /// Counterparty subject: a name, domain, or username.
    pub subject: String,
    /// One of: person | company | domain | username.
    #[serde(rename = "type")]
    pub subject_type: String,
}

const DEEP_AUDIT_URL: &str = "https://api.hergertsynthora.com/v1/deep-audit";

pub fn request_deep_audit(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: DeepAuditReq =
        serde_json::from_slice(input).map_err(|e| format!("request-deep-audit: bad input: {e}"))?;

    match req.subject_type.as_str() {
        "person" | "company" | "domain" | "username" => {}
        other => {
            return Err(format!(
                "request-deep-audit: `type` must be person|company|domain|username, got {other:?}"
            ))
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        let resp = deep_audit_wasm(req)?;
        serde_json::to_vec(&resp).map_err(|e| e.to_string())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = req;
        Err("request_deep_audit is only implemented on the wasm32 target".to_string())
    }
}

#[cfg(target_arch = "wasm32")]
use crate::host::interfaces::{http_with_placeholders as hwp, kv_store, logging};
#[cfg(target_arch = "wasm32")]
use crate::host::tenant::tenant_context;

/// Typed mapping of the host's HttpError — failures never leak resolved PII,
/// and each variant tells the operator exactly what to fix.
#[cfg(target_arch = "wasm32")]
fn format_http_error(e: hwp::HttpError) -> String {
    match e {
        hwp::HttpError::EgressDenied(host) => format!(
            "egress denied for host {host} — add it to the caller's delegation grant allowed_hosts"
        ),
        hwp::HttpError::PlaceholderDenied(marker) => {
            format!("placeholder not permitted: {marker}")
        }
        hwp::HttpError::PlaceholderUnknown(field) => format!(
            "user profile missing field: {field} — the caller must verify an email contact first"
        ),
        hwp::HttpError::PlaceholderNoUserContext => {
            "no user context bound for placeholder resolution — invoke through a user session"
                .to_string()
        }
        hwp::HttpError::UpstreamError(reason) => format!("upstream: {reason}"),
    }
}

#[cfg(target_arch = "wasm32")]
fn deep_audit_wasm(req: DeepAuditReq) -> Result<serde_json::Value, String> {
    // Attribution wallet (optional) — same secrets map as screen-counterparty.
    let tid = tenant_context::tenant_did();
    let map_name = format!("z:{}:secrets", hex::encode(&tid));
    let wallet = kv_store::get(&map_name, b"synthora_wallet")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok());

    let mut headers: Vec<(String, String)> = alloc::vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("accept".to_string(), "application/json".to_string()),
    ];
    if let Some(w) = wallet {
        headers.push(("x-wallet".to_string(), w));
    }

    // The officer's email is a placeholder — resolved host-side from the
    // calling user's verified profile. It is never a function argument.
    let body = serde_json::json!({
        "subject": req.subject,
        "type": req.subject_type,
        "requester_email": "{{profile.verified_contacts.email.value}}",
    });

    let resp = hwp::call(&hwp::Request {
        method: hwp::Verb::Post,
        url: DEEP_AUDIT_URL.to_string(),
        headers: Some(headers),
        payload: Some(serde_json::to_vec(&body).map_err(|e| e.to_string())?),
    })
    .map_err(format_http_error)?;

    let _ = logging::info(&format!("deep-audit filed, upstream HTTP {}", resp.code));

    let text = String::from_utf8_lossy(&resp.payload).to_string();
    Ok(serde_json::json!({
        "http_code": resp.code,
        "status": match resp.code {
            200 => "submitted",
            402 => "payment_required",
            _ => "http_error",
        },
        "upstream": serde_json::from_str::<serde_json::Value>(&text)
            .unwrap_or(serde_json::Value::String(text.chars().take(512).collect())),
    }))
}
