#![no_std]

extern crate alloc;
extern crate wasm_bindgen;
mod config;
mod handlers;
mod node;
mod websocket;
// Temporarily commented out due to wasm incompatibility
// pub use cggmp21;
pub use cggmp21_keygen;
pub use key_share;

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use wasm_bindgen::prelude::*;

use cggmp21_keygen::security_level::SecurityLevel128;
use generic_ec::curves::Secp256k1;
use sha2::Sha256;

pub use websocket::{WebSocketClient, P2PNode};

// Define type aliases for common types (unused for now but may be needed later)
#[allow(dead_code)]
type Curve = Secp256k1;
#[allow(dead_code)]
type SecurityLevel = SecurityLevel128;
#[allow(dead_code)]
type HashFunction = Sha256;

#[wasm_bindgen]
pub fn is_wasm_loaded() -> bool {
    true
}

#[wasm_bindgen]
pub fn get_version() -> u32 {
    1
}

// Key generation wrapper functions

#[wasm_bindgen]
pub struct KeygenConfig {
    party_index: u16,
    num_parties: u16,
    threshold: Option<u16>,
}

#[wasm_bindgen]
impl KeygenConfig {
    #[wasm_bindgen(constructor)]
    pub fn new(party_index: u16, num_parties: u16) -> Self {
        Self {
            party_index,
            num_parties,
            threshold: None,
        }
    }

    #[wasm_bindgen]
    pub fn with_threshold(mut self, threshold: u16) -> Self {
        self.threshold = Some(threshold);
        self
    }
}

#[wasm_bindgen]
pub fn create_execution_id(id_string: &str) -> String {
    // Convert string to bytes for ExecutionId::new
    let id_bytes = id_string.as_bytes();
    let _execution_id = cggmp21_keygen::ExecutionId::new(id_bytes);
    // ExecutionId doesn't implement Debug, return a simple representation
    alloc::format!("ExecutionID: {}", id_string)
}

#[wasm_bindgen]
pub fn serialize_message(message: &[u8]) -> String {
    // Convert raw message bytes to hex for JS transmission
    hex::encode(message)
}

#[wasm_bindgen]
pub fn deserialize_message(message_hex: &str) -> Result<Vec<u8>, JsValue> {
    // Convert hex string back to bytes
    match hex::decode(message_hex) {
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(JsValue::from_str(&format!(
            "Error deserializing message: {:?}",
            e
        ))),
    }
}

// Message handler for threshold keygen protocol
#[wasm_bindgen]
pub struct ThresholdKeygenSession {
    party_index: u16,
    num_parties: u16,
    threshold: u16,
    seed: Vec<u8>,
    session_id: String,
}

#[wasm_bindgen]
impl ThresholdKeygenSession {
    #[wasm_bindgen(constructor)]
    pub fn new(party_id: u16, num_parties: u16, threshold: u16, session_id: &str) -> Self {
        // Create a random seed from the current time
        let current_time = js_sys::Date::now() as u64;
        let mut seed = Vec::new();
        seed.extend_from_slice(&current_time.to_be_bytes());
        seed.extend_from_slice(session_id.as_bytes());

        Self {
            party_index: party_id,
            num_parties,
            threshold,
            seed,
            session_id: session_id.to_string(),
        }
    }

    #[wasm_bindgen]
    pub fn generate_round1_message(&self) -> String {
        // This is a simplified stub - in a real implementation, we would:
        // 1. Create a hash RNG from our seed
        // 2. Generate the actual round 1 message using the cggmp21_keygen protocol
        // 3. Serialize the message for transmission

        // For now, just return a placeholder
        format!("ROUND1_MESSAGE_FROM_PARTY_{}", self.party_index)
    }

    #[wasm_bindgen]
    pub fn process_round1_messages(&self, messages: &JsValue) -> Result<String, JsValue> {
        // This would process round 1 messages from other parties
        // For now just echo back what we received
        Ok(format!("Processed round 1 messages: {:?}", messages))
    }

    // Add additional methods for round 2, 3, etc.
}

#[wasm_bindgen(start)]
fn start_websocket() -> Result<(), JsValue> {
    // Connect to an echo server
    let ws = WebSocket::new("wss://echo.websocket.events")?;
    // For small binary messages, like CBOR, Arraybuffer is more efficient than Blob handling
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);
    // create callback
    let cloned_ws = ws.clone();
    let onmessage_callback = Closure::<dyn FnMut(_)>::new(move |e: MessageEvent| {
        // Handle difference Text/Binary,...
        if let Ok(abuf) = e.data().dyn_into::<js_sys::ArrayBuffer>() {
            console_log!("message event, received arraybuffer: {:?}", abuf);
            let array = js_sys::Uint8Array::new(&abuf);
            let len = array.byte_length() as usize;
            console_log!("Arraybuffer received {}bytes: {:?}", len, array.to_vec());
            // here you can for example use Serde Deserialize decode the message
            // for demo purposes we switch back to Blob-type and send off another binary message
            cloned_ws.set_binary_type(web_sys::BinaryType::Blob);
            match cloned_ws.send_with_u8_array(&[5, 6, 7, 8]) {
                Ok(_) => console_log!("binary message successfully sent"),
                Err(err) => console_log!("error sending message: {:?}", err),
            }
        } else if let Ok(blob) = e.data().dyn_into::<web_sys::Blob>() {
            console_log!("message event, received blob: {:?}", blob);
            // better alternative to juggling with FileReader is to use https://crates.io/crates/gloo-file
            let fr = web_sys::FileReader::new().unwrap();
            let fr_c = fr.clone();
            // create onLoadEnd callback
            let onloadend_cb = Closure::<dyn FnMut(_)>::new(move |_e: web_sys::ProgressEvent| {
                let array = js_sys::Uint8Array::new(&fr_c.result().unwrap());
                let len = array.byte_length() as usize;
                console_log!("Blob received {}bytes: {:?}", len, array.to_vec());
                // here you can for example use the received image/png data
            });
            fr.set_onloadend(Some(onloadend_cb.as_ref().unchecked_ref()));
            fr.read_as_array_buffer(&blob).expect("blob not readable");
            onloadend_cb.forget();
        } else if let Ok(txt) = e.data().dyn_into::<js_sys::JsString>() {
            console_log!("message event, received Text: {:?}", txt);
        } else {
            console_log!("message event, received Unknown: {:?}", e.data());
        }
    });
    // set message event handler on WebSocket
    ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
    // forget the callback to keep it alive
    onmessage_callback.forget();

    let onerror_callback = Closure::<dyn FnMut(_)>::new(move |e: ErrorEvent| {
        console_log!("error event: {:?}", e);
    });
    ws.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
    onerror_callback.forget();

    let cloned_ws = ws.clone();
    let onopen_callback = Closure::<dyn FnMut()>::new(move || {
        console_log!("socket opened");
        match cloned_ws.send_with_str("ping") {
            Ok(_) => console_log!("message successfully sent"),
            Err(err) => console_log!("error sending message: {:?}", err),
        }
        // send off binary message
        match cloned_ws.send_with_u8_array(&[0, 1, 2, 3]) {
            Ok(_) => console_log!("binary message successfully sent"),
            Err(err) => console_log!("error sending message: {:?}", err),
        }
    });
    ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
    onopen_callback.forget();

    Ok(())
}
