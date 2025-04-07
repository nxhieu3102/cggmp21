use anyhow::{Context, Result};
use futures::{Sink, Stream, StreamExt};
use futures_channel::mpsc;
use round_based::{Incoming, Outgoing};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    net::TcpListener,
    sync::{RwLock, mpsc as tokio_mpsc},
};

use crate::{config, handlers};
use crate::handlers::{KeyManager, SignedMessage};

pub struct Node<M> {
    pub address: SocketAddr,
    pub peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<SignedMessage<M>>>>>,
    pub peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
    pub key_manager: Arc<RwLock<KeyManager>>,
}

impl<M> Node<M>
where
    M: Send + Sync + Clone + 'static + Serialize + for<'de> serde::de::Deserialize<'de>,
{
    /// Initialize a new P2P node with the provided configuration
    pub async fn new(
        config: config::Config,
    ) -> Result<(
        Self,
        impl Stream<Item = Result<Incoming<M>>>,
        impl Sink<Outgoing<M>, Error = mpsc::SendError>,
    )> {
        let (incoming_tx, incoming_rx) = mpsc::channel(32);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(32);

        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peers_id = Arc::new(RwLock::new(HashMap::new()));
        
        // Initialize key manager with node ID
        let key_manager = Arc::new(RwLock::new(KeyManager::new(config.node.id as u16)));
        
        // Initialize keys
        Self::initialize_keys(&config, &key_manager).await?;

        // Build peer ID to address mapping
        Self::initialize_peer_mappings(&config, &peers_id).await;

        let node = Node {
            address: config.node.address,
            peers: peers.clone(),
            peers_id: peers_id.clone(),
            key_manager: key_manager.clone(),
        };

        // Setup network listeners and handlers
        Self::setup_network(
            &config, 
            &node,
            incoming_tx, 
            outgoing_rx, 
            peers.clone(), 
            peers_id.clone(),
            key_manager.clone(),
        ).await?;

        Ok((node, incoming_rx.map(Ok), outgoing_tx))
    }
    
    /// Initialize the keys for this node and its peers
    async fn initialize_keys(
        config: &config::Config, 
        key_manager: &Arc<RwLock<KeyManager>>,
    ) -> Result<()> {
        let mut key_manager = key_manager.write().await;
        
        // Load our own private key if available
        if let Some(private_key) = &config.node.private_key {
            key_manager.load_keypair_from_hex(private_key)
                .context("Failed to load node's private key")?;
        }
        
        // Add our own public key to the key manager
        if let Some(public_key) = &config.node.public_key {
            key_manager.add_public_key(config.node.id as u16, public_key)
                .context("Failed to add node's public key")?;
        }
        
        // In a real implementation, we would need to distribute public keys
        // Here we would add peers' public keys to the key manager
        // For now, this would typically involve reading from config or a keystore
        
        Ok(())
    }

    /// Initialize the peer ID to address mappings
    async fn initialize_peer_mappings(
        config: &config::Config, 
        peers_id: &Arc<RwLock<HashMap<u16, SocketAddr>>>
    ) {
        let mut peers_id_map = peers_id.write().await;
        
        // Add self to the peer mapping
        peers_id_map.insert(config.node.id.try_into().unwrap(), config.node.address);
        
        // Add all other peers to the mapping
        for peer in &config.peers {
            peers_id_map.insert(peer.id.try_into().unwrap(), peer.address);
        }
    }

    /// Setup network listeners and connection handlers
    async fn setup_network(
        config: &config::Config,
        node: &Node<M>,
        incoming_tx: mpsc::Sender<Incoming<M>>,
        outgoing_rx: mpsc::Receiver<Outgoing<M>>,
        peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<SignedMessage<M>>>>>,
        peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
        key_manager: Arc<RwLock<KeyManager>>,
    ) -> Result<()> {
        // Start the TCP listener for incoming connections
        let listener = TcpListener::bind(node.address)
            .await
            .context(format!("Failed to bind to address: {}", node.address))?;
        
        // Handle incoming connections
        Self::handle_incoming_connections(listener, incoming_tx.clone(), peers.clone(), peers_id.clone(), key_manager.clone());
        
        // Connect to peers with lower IDs
        Self::connect_to_peers(config, incoming_tx.clone(), peers.clone(), peers_id.clone(), key_manager.clone());
        
        // Handle outgoing messages
        Self::handle_outgoing_messages(outgoing_rx, peers, peers_id, key_manager);
        
        Ok(())
    }

    /// Spawn a task to handle incoming connections
    fn handle_incoming_connections(
        listener: TcpListener,
        incoming_tx: mpsc::Sender<Incoming<M>>,
        peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<SignedMessage<M>>>>>,
        peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
        key_manager: Arc<RwLock<KeyManager>>,
    ) {
        tokio::spawn(async move {
            while let Ok((stream, address)) = listener.accept().await {
                println!("Incoming connection from: {}", address);
                let peers_clone = peers.clone();
                let peers_id_clone = peers_id.clone();
                let incoming_tx_clone = incoming_tx.clone();
                let key_manager_clone = key_manager.clone();
                
                tokio::spawn(async move {
                    handlers::handle_connection(
                        stream,
                        address,
                        incoming_tx_clone,
                        peers_clone,
                        peers_id_clone,
                        key_manager_clone,
                    )
                    .await;
                });
            }
        });
    }

    /// Connect to peers with lower IDs
    fn connect_to_peers(
        config: &config::Config,
        incoming_tx: mpsc::Sender<Incoming<M>>,
        peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<SignedMessage<M>>>>>,
        peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
        key_manager: Arc<RwLock<KeyManager>>,
    ) {
        // Clone the important values from config rather than the reference itself
        let node_id = config.node.id;
        let peers_to_connect = config.peers.clone();
        
        tokio::spawn(async move {
            for peer in peers_to_connect.iter() {
                // We only initiate connections to peers with lower IDs
                // to avoid duplicate connections
                if peer.id < node_id {
                    let peers_clone = peers.clone();
                    let peers_id_clone = peers_id.clone();
                    let incoming_tx_clone = incoming_tx.clone();
                    let key_manager_clone = key_manager.clone();
                    let peer_address = peer.address;
                    
                    tokio::spawn(async move {
                        let mut connected = false;
                        while !connected {
                            match handlers::connect(peer_address, incoming_tx_clone.clone(), 
                                      peers_clone.clone(), peers_id_clone.clone(), 
                                      key_manager_clone.clone()).await {
                                Ok(_) => {
                                    println!("Connected to peer: {}", peer_address);
                                    connected = true;
                                },
                                Err(e) => {
                                    eprintln!("Error connecting to peer {}: {}. Retrying in 1 second...", peer_address, e);
                                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                                }
                            }
                        }
                    });
                }
            }
        });
    }

    /// Handle outgoing messages
    fn handle_outgoing_messages(
        mut outgoing_rx: mpsc::Receiver<Outgoing<M>>,
        peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<SignedMessage<M>>>>>,
        peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
        key_manager: Arc<RwLock<KeyManager>>,
    ) {
        tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.next().await {
                if let Err(e) = handlers::handle_outgoing(msg, &peers, &peers_id, &key_manager).await {
                    eprintln!("Error sending message: {}", e);
                }
            }
        });
    }
}
