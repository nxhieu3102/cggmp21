#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use wasm_bindgen::prelude::*;

use crate::config::PeerInfo;

#[wasm_bindgen]
pub struct MessageHandler {
    party_id: u16,
    peers: Vec<PeerInfo>,
}

#[wasm_bindgen]
impl MessageHandler {
    #[wasm_bindgen(constructor)]
    pub fn new(party_id: u16) -> Self {
        Self {
            party_id,
            peers: Vec::new(),
        }
    }

    #[wasm_bindgen]
    pub fn add_peer(&mut self, peer_id: u16, address: &str) {
        self.peers.push(PeerInfo::new(peer_id, address));
    }

    #[wasm_bindgen]
    pub fn process_message(&self, message: &[u8]) -> Result<String, JsValue> {
        // In a real implementation, we would:
        // 1. Deserialize the message
        // 2. Process it according to the protocol
        // 3. Return any response
        
        // For now, just return a dummy response
        Ok(format!(
            "Party {} processed message of length {}",
            self.party_id,
            message.len()
        ))
    }
}
