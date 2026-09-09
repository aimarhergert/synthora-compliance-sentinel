//! z-synthora-compliance v0.1.0 — enterprise counterparty due-diligence
//! contract for the T3 Network (T3N).
//!
//! Three operations:
//!   - `screen-counterparty`: sanctions screening (legal name) + crypto
//!     due-diligence (EVM address) against the SYNTHORA x402 intelligence API.
//!     No PII crosses the WIT boundary.
//!   - `request-deep-audit`: files a deep OSINT audit request where the
//!     compliance officer's verified email is a `{{profile.<field>}}` marker
//!     resolved by the host inside the enclave — plaintext PII never enters
//!     WASM memory.
//!   - `compile-brief`: aggregates results into an immutable brief in the
//!     tenant KV map `z:<tid>:briefs` and anchors it in the transaction
//!     Merkle leaf via `set-claims-digest`, so any receipt holder can verify
//!     the brief offline.
//!
//! The upstream X-WALLET attribution header is read from the z: KV map
//! `secrets` (key: `synthora_wallet`), seeded by the tenant SDK before first
//! use. If the upstream answers HTTP 402 (x402 payment required), the leg is
//! reported as `payment_required` with the payment terms verbatim instead of
//! failing — the agent calling this contract can then decide to pay or stop.
//!
//! # Setup (tenant SDK, before first use)
//! ```text
//! tenant.maps.create({ tail: "secrets", ... readers/writers: [contractId] })
//! tenant.maps.create({ tail: "briefs",  ... readers/writers: [contractId] })
//! tenant.executeControl("map-entry-set", { map_name: "z:<tid>:secrets",
//!   key: "synthora_wallet", value: "0x..." })
//! ```
#![warn(clippy::style, missing_debug_implementations)]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

extern crate alloc;

pub const CONTRACT_VERSION: &str = "0.1.0";

wit_bindgen::generate!({
    world: "synthora-compliance",
    path: "wit",
    additional_derives: [
        serde::Deserialize,
        serde::Serialize,
    ],
    generate_all,
});

mod audit;
mod brief;
mod screen;

struct Component;

#[cfg(target_arch = "wasm32")]
impl exports::z::synthora_compliance::contracts::Guest for Component {
    fn screen_counterparty(
        req: exports::z::synthora_compliance::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("screen-counterparty: missing input")?;
        screen::screen_counterparty(&input)
    }

    fn request_deep_audit(
        req: exports::z::synthora_compliance::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("request-deep-audit: missing input")?;
        audit::request_deep_audit(&input)
    }

    fn compile_brief(
        req: exports::z::synthora_compliance::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("compile-brief: missing input")?;
        brief::compile_brief(&input)
    }
}

#[cfg(target_arch = "wasm32")]
export!(Component);

#[cfg(test)]
mod tests {
    use super::CONTRACT_VERSION;

    #[test]
    fn contract_version_is_semver() {
        let parts: Vec<&str> = CONTRACT_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "CONTRACT_VERSION must be MAJOR.MINOR.PATCH");
        for part in parts {
            assert!(part.parse::<u32>().is_ok(), "each part must be a number");
        }
    }

    #[test]
    fn contract_version_matches_cargo_toml() {
        assert_eq!(CONTRACT_VERSION, env!("CARGO_PKG_VERSION"));
    }
}
