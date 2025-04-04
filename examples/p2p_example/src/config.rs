use anyhow::Result;
use serde::Deserialize;
use std::{fs, net::SocketAddr};

#[derive(Deserialize, Clone)]
pub struct Config {
    pub node: NodeConfig,
    pub peers: Vec<PeerConfig>,
}

#[derive(Deserialize, Clone)]
pub struct NodeConfig {
    pub id: usize,
    pub address: SocketAddr,
}

#[derive(Deserialize, Clone)]
pub struct PeerConfig {
    pub id: usize,
    pub address: SocketAddr,
}

pub fn load_config(config_file: &str) -> Result<Config> {
    let config = fs::read_to_string(config_file)?;
    let config: Config = serde_yaml::from_str(&config)?;
    Ok(config)
}
