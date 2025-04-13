use wasm_bindgen::prelude::*;
use p2p_network::message::InternalMessage;
use p2p_network::Message;
use p2p_network::VERSION;

#[wasm_bindgen]
pub fn get_version() -> String {
    VERSION.to_string()
}

#[wasm_bindgen]
pub fn create_message(message_type: &str, sender_id: &str, text: &str) -> JsValue {
    let payload = text.as_bytes().to_vec();
    let message = InternalMessage::new(message_type, Some(sender_id), payload);
    
    serde_wasm_bindgen::to_value(&message).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn serialize_message(message_js: JsValue) -> Vec<u8> {
    match serde_wasm_bindgen::from_value::<InternalMessage>(message_js) {
        Ok(message) => message.as_bytes(),
        Err(_) => Vec::new(),
    }
}

#[wasm_bindgen]
pub fn deserialize_message(bytes: &[u8]) -> JsValue {
    match InternalMessage::from_bytes(bytes) {
        Ok(message) => serde_wasm_bindgen::to_value(&message).unwrap_or(JsValue::NULL),
        Err(_) => JsValue::NULL,
    }
}

#[wasm_bindgen(start)]
pub fn start() {
    // Initialize console error panic hook for better error messages
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
} 
