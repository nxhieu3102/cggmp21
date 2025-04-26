#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use wasm_bindgen::prelude::*;

use crate::config::PeerInfo;

#[wasm_bindgen]
pub struct Node {
    party_id: u16,
    num_parties: u16,
    threshold: u16,
    peers: Vec<PeerInfo>,
}

#[wasm_bindgen]
impl Node {
    #[wasm_bindgen(constructor)]
    pub fn new(party_id: u16, num_parties: u16, threshold: u16) -> Self {
        Self {
            party_id,
            num_parties,
            threshold,
            peers: Vec::new(),
        }
    }

    // Config can't be passed directly via wasm_bindgen, so use individual parameters
    #[wasm_bindgen]
    pub fn with_config(node_id: u16, num_parties: u16, threshold: u16) -> Self {
        Self {
            party_id: node_id,
            num_parties,
            threshold,
            peers: Vec::new(),
        }
    }

    #[wasm_bindgen]
    pub fn add_peer(&mut self, peer_id: u16, address: &str) {
        self.peers.push(PeerInfo::new(peer_id, address));
    }

    #[wasm_bindgen]
    pub fn get_node_info(&self) -> String {
        format!(
            "Node ID: {}, Parties: {}, Threshold: {}, Peers: {}",
            self.party_id,
            self.num_parties,
            self.threshold,
            self.peers.len()
        )
    }
}
