#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;

#[derive(Clone)]
pub struct Config {
    pub node_id: u16,
    pub threshold: u16,
    pub num_parties: u16,
}

impl Config {
    pub fn new(node_id: u16, num_parties: u16, threshold: u16) -> Self {
        Self {
            node_id,
            num_parties,
            threshold,
        }
    }
}

#[derive(Clone)]
pub struct PeerInfo {
    pub id: u16,
    pub address: String,
}

impl PeerInfo {
    pub fn new(id: u16, address: &str) -> Self {
        Self {
            id,
            address: String::from(address),
        }
    }
}
