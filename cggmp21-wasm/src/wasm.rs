//! JavaScript API (wasm32 only)
//!
//! Byte strings are `Uint8Array`s. Sessions take a config object (camelCase fields of the
//! corresponding Rust config) and return step objects
//! `{ outgoing: Envelope[], events: TraceEvent[], output?: object }` where an envelope is
//! `{ sender, recipient /* null = broadcast */, round, payload: Uint8Array }`.
//! Errors are thrown as `Error` with a message that never contains secret data.
//!
//! Randomness comes from `crypto.getRandomValues` (`OsRng`).

use rand_core::OsRng;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::{Envelope, Error, Step};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    pub(crate) fn performance_now() -> f64;
}

fn js_err(err: Error) -> JsError {
    JsError::new(&err.to_string())
}

fn to_js<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::new().serialize_missing_as_null(true))
        .map_err(|_| JsError::new("internal error: converting output to JS failed"))
}

fn from_js<T: serde::de::DeserializeOwned>(value: JsValue, what: &str) -> Result<T, JsError> {
    serde_wasm_bindgen::from_value(value).map_err(|_| JsError::new(&format!("invalid {what}")))
}

fn step_to_js<O: Serialize>(step: Result<Step<O>, Error>) -> Result<JsValue, JsError> {
    to_js(&step.map_err(js_err)?)
}

macro_rules! js_session {
    ($js_name:ident, $rust:ident, $wrapper:ident, $config:ident) => {
        #[doc = concat!("JS wrapper of [`crate::", stringify!($rust), "`]")]
        #[wasm_bindgen(js_name = $js_name)]
        pub struct $wrapper(crate::$rust);

        #[wasm_bindgen(js_class = $js_name)]
        impl $wrapper {
            /// Creates a session from a config object
            #[wasm_bindgen(constructor)]
            pub fn new(config: JsValue) -> Result<$wrapper, JsError> {
                let config: crate::$config = from_js(config, "session config")?;
                crate::$rust::new(config, OsRng)
                    .map($wrapper)
                    .map_err(js_err)
            }

            /// Starts the protocol; returns a step object
            pub fn start(&mut self) -> Result<JsValue, JsError> {
                step_to_js(self.0.start())
            }

            /// Feeds an envelope received from another party; returns a step object
            #[wasm_bindgen(js_name = handleIncoming)]
            pub fn handle_incoming(&mut self, envelope: JsValue) -> Result<JsValue, JsError> {
                let envelope: Envelope = from_js(envelope, "envelope")?;
                step_to_js(self.0.handle_incoming(&envelope))
            }

            /// Whether the output was already returned
            #[wasm_bindgen(getter)]
            pub fn finished(&self) -> bool {
                self.0.is_finished()
            }
        }
    };
}

js_session!(KeygenSession, KeygenSession, JsKeygenSession, KeygenConfig);
js_session!(
    AuxInfoSession,
    AuxInfoSession,
    JsAuxInfoSession,
    AuxInfoConfig
);
js_session!(
    SigningSession,
    SigningSession,
    JsSigningSession,
    SigningConfig
);
js_session!(
    PresigningSession,
    PresigningSession,
    JsPresigningSession,
    SigningConfig
);

/// Generates a Paillier key for aux info generation; returns a secret blob
///
/// `onProgress(event)` (optional) receives `{kind, which, attempts?}` objects, candidate
/// progress at most every `minIntervalMs` milliseconds.
#[wasm_bindgen(js_name = generatePaillierKey)]
pub fn generate_paillier_key(
    on_progress: Option<js_sys::Function>,
    min_interval_ms: Option<f64>,
) -> Result<Vec<u8>, JsError> {
    crate::generate_paillier_key(&mut OsRng, min_interval_ms.unwrap_or(100.), &mut |event| {
        if let (Some(f), Ok(event)) = (&on_progress, to_js(&event)) {
            // Progress reporting is best effort: a throwing callback must not abort keygen
            let _ = f.call1(&JsValue::NULL, &event);
        }
    })
    .map_err(js_err)
}

/// Combines keygen and aux info outputs of one party into a key share; returns a secret blob
#[wasm_bindgen(js_name = completeKeyShare)]
pub fn complete_key_share(
    incomplete_key_share: &[u8],
    aux_info: &[u8],
) -> Result<Vec<u8>, JsError> {
    crate::complete_key_share(incomplete_key_share, aux_info).map_err(js_err)
}

/// Public info of a key share blob: `{complete, i, n, t, ranks, publicKey}`
#[wasm_bindgen(js_name = keyShareInfo)]
pub fn key_share_info(key_share: &[u8]) -> Result<JsValue, JsError> {
    to_js(&crate::key_share_info(key_share).map_err(js_err)?)
}

/// Issues a partial signature from a presignature. Never reuse a presignature.
#[wasm_bindgen(js_name = issuePartialSignature)]
pub fn issue_partial_signature(presignature: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    crate::issue_partial_signature(presignature, message).map_err(js_err)
}

/// Combines partial signatures (array of `Uint8Array`) and verifies the result; returns `r || s`
#[wasm_bindgen(js_name = combinePartialSignatures)]
pub fn combine_partial_signatures(
    public_key: &[u8],
    message: &[u8],
    partial_signatures: JsValue,
) -> Result<Vec<u8>, JsError> {
    let partials: Vec<serde_bytes::ByteBuf> =
        from_js(partial_signatures, "partial signatures array")?;
    crate::combine_partial_signatures(public_key, message, partials.iter().map(|p| p.as_slice()))
        .map_err(js_err)
}

/// Verifies an ECDSA signature `r || s` of SHA-256(`message`) under a SEC1 public key
#[wasm_bindgen(js_name = verifySignature)]
pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, JsError> {
    crate::verify_signature(public_key, message, signature).map_err(js_err)
}
