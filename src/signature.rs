//! `X-Twilio-Signature` validation.
//!
//! Twilio signs each webhook so the receiver can prove the request really came
//! from Twilio (the routes carry no bearer token). The scheme:
//!
//! 1. Take the full request URL exactly as Twilio reached it
//!    (`public_base_url` + the route's mount path + the raw query string).
//! 2. For an `application/x-www-form-urlencoded` body, sort the POST params by
//!    key and append, for each, the key immediately followed by its value with
//!    NO delimiters.
//! 3. HMAC-SHA1 that string keyed by the Account **Auth Token** (NOT an API
//!    Key secret — API keys do not sign webhooks).
//! 4. Base64-encode the digest and compare (constant-time) to the
//!    `X-Twilio-Signature` header.
//!
//! For a JSON / non-form body Twilio instead appends a `bodySHA256` query
//! parameter (the hex SHA-256 of the raw body) to the signed URL and signs the
//! resulting URL with no appended params. Both variants are implemented here.

use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha1 = Hmac<Sha1>;

/// Compute the expected base64 signature for a form-encoded webhook.
///
/// `url` is the full reconstructed public URL (including any raw query string).
/// `params` are the decoded POST form params; the function sorts them by key.
pub fn expected_signature_form(auth_token: &str, url: &str, params: &[(String, String)]) -> String {
    let mut data = String::from(url);
    let mut sorted: Vec<&(String, String)> = params.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in sorted {
        data.push_str(k);
        data.push_str(v);
    }
    hmac_b64(auth_token, data.as_bytes())
}

/// Compute the expected base64 signature for a JSON-body webhook. Twilio
/// appends `bodySHA256=<hex>` to the URL (caller must include it in `url`) and
/// signs the URL alone (no appended params).
pub fn expected_signature_json(auth_token: &str, url_with_body_sha: &str) -> String {
    hmac_b64(auth_token, url_with_body_sha.as_bytes())
}

/// Hex SHA-256 of a raw body — the value Twilio places in the `bodySHA256`
/// query param for JSON webhooks.
pub fn body_sha256_hex(body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(body);
    let digest = h.finalize();
    hex_lower(&digest)
}

fn hmac_b64(key: &str, data: &[u8]) -> String {
    let mut mac =
        HmacSha1::new_from_slice(key.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    base64::engine::general_purpose::STANDARD.encode(digest)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Constant-time compare a provided signature against the expected one. Both
/// are base64 strings; we compare the raw bytes to avoid leaking length/early-
/// mismatch timing.
pub fn verify(expected_b64: &str, provided_b64: &str) -> bool {
    let expected = expected_b64.as_bytes();
    let provided = provided_b64.as_bytes();
    if expected.len() != provided.len() {
        // Lengths differ → definitely a mismatch. The early return leaks only
        // the (public) expected length, never the secret.
        return false;
    }
    expected.ct_eq(provided).into()
}

/// Validate a form-body webhook signature end to end. Returns `Ok(())` on a
/// match, `Err(reason)` otherwise.
pub fn validate_form(
    auth_token: &str,
    url: &str,
    params: &[(String, String)],
    provided: &str,
) -> Result<(), String> {
    let expected = expected_signature_form(auth_token, url, params);
    if verify(&expected, provided) {
        Ok(())
    } else {
        Err("signature mismatch".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vector. The signed string is the URL
    // `https://mycompany.com/myapp.php?foo=1&bar=2` followed by the POST params
    // sorted by key (Caller, Digits, From, To), each key immediately followed
    // by its value with no delimiter; HMAC-SHA1 keyed by auth token "12345";
    // base64 → `V4AdhXOYoGGDl714zmEWoHCrr0A=`.
    const GOLDEN_SIG: &str = "V4AdhXOYoGGDl714zmEWoHCrr0A=";

    fn golden_params() -> Vec<(String, String)> {
        vec![
            ("Caller".into(), "+14158675309".into()),
            ("Digits".into(), "1234".into()),
            ("From".into(), "+14158675309".into()),
            ("To".into(), "+18005551212".into()),
        ]
    }

    #[test]
    fn golden_vector_matches() {
        let sig = expected_signature_form(
            "12345",
            "https://mycompany.com/myapp.php?foo=1&bar=2",
            &golden_params(),
        );
        assert_eq!(sig, GOLDEN_SIG);
    }

    #[test]
    fn validate_form_accepts_golden() {
        assert!(
            validate_form(
                "12345",
                "https://mycompany.com/myapp.php?foo=1&bar=2",
                &golden_params(),
                GOLDEN_SIG,
            )
            .is_ok()
        );
    }

    #[test]
    fn tampered_body_is_rejected() {
        // Flip one param value: the signature must no longer validate.
        let mut params = golden_params();
        params[1].1 = "9999".into();
        let err = validate_form(
            "12345",
            "https://mycompany.com/myapp.php?foo=1&bar=2",
            &params,
            GOLDEN_SIG,
        )
        .unwrap_err();
        assert!(err.contains("mismatch"));
    }

    #[test]
    fn wrong_token_is_rejected() {
        let err = validate_form(
            "wrong-token",
            "https://mycompany.com/myapp.php?foo=1&bar=2",
            &golden_params(),
            GOLDEN_SIG,
        )
        .unwrap_err();
        assert!(err.contains("mismatch"));
    }

    #[test]
    fn param_order_does_not_matter() {
        // The signature sorts params by key, so a reordered input matches.
        let mut reordered = golden_params();
        reordered.reverse();
        let sig = expected_signature_form(
            "12345",
            "https://mycompany.com/myapp.php?foo=1&bar=2",
            &reordered,
        );
        assert_eq!(sig, GOLDEN_SIG);
    }

    #[test]
    fn verify_is_length_safe() {
        assert!(!verify("abc", "abcd"));
        assert!(verify("abc", "abc"));
        assert!(!verify("abc", "abd"));
    }

    #[test]
    fn body_sha256_and_json_variant() {
        let body = br#"{"From":"+1555"}"#;
        let hex = body_sha256_hex(body);
        assert_eq!(hex.len(), 64);
        // The JSON variant signs the URL (which already carries bodySHA256).
        let url = format!("https://x.example.com/hooks/sms?bodySHA256={hex}");
        let sig = expected_signature_json("tok", &url);
        // Recomputing yields the same signature (determinism check).
        assert_eq!(sig, expected_signature_json("tok", &url));
    }
}
