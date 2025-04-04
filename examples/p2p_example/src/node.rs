use anyhow::{Context, Result};
use futures::{Sink, Stream, StreamExt};
use futures_channel::mpsc;
use round_based::{Incoming, Outgoing};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    net::TcpListener,
    sync::{RwLock, mpsc as tokio_mpsc},
};

use crate::{config, handlers};

pub struct Node<M> {
    pub address: SocketAddr,
    pub peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<M>>>>,
    pub peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
    pub target_peers: Arc<RwLock<HashSet<SocketAddr>>>,
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
        let target_peers = Arc::new(RwLock::new(HashSet::new()));

        // Build peer ID to address mapping
        Self::initialize_peer_mappings(&config, &peers_id).await;
        
        // Initialize target peers set
        let mut target_peers_set = target_peers.write().await;
        for peer in &config.peers {
            target_peers_set.insert(peer.address);
        }
        drop(target_peers_set);

        let node = Node {
            address: config.node.address,
            peers: peers.clone(),
            peers_id: peers_id.clone(),
            target_peers: target_peers.clone(),
        };

        // Setup network listeners and handlers
        Self::setup_network(
            &config, 
            &node,
            incoming_tx, 
            outgoing_rx, 
            peers.clone(), 
            peers_id.clone(),
            target_peers.clone()
        ).await?;

        Ok((node, incoming_rx.map(Ok), outgoing_tx))
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
        peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<M>>>>,
        peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
        target_peers: Arc<RwLock<HashSet<SocketAddr>>>,
    ) -> Result<()> {
        // Start the TCP listener for incoming connections
        let listener = TcpListener::bind(node.address)
            .await
            .context(format!("Failed to bind to address: {}", node.address))?;
        
        // Handle incoming connections
        Self::handle_incoming_connections(listener, incoming_tx.clone(), peers.clone(), peers_id.clone());
        
        // Connect to all peers in the network
        Self::connect_to_peers(config, incoming_tx.clone(), peers.clone(), peers_id.clone());
        
        // Start the retry mechanism to reconnect to missing peers
        Self::start_reconnect_mechanism(config, incoming_tx.clone(), peers.clone(), peers_id.clone(), target_peers.clone());
        
        // Handle outgoing messages
        Self::handle_outgoing_messages(outgoing_rx, peers, peers_id);
        
        Ok(())
    }

    /// Start a background task that periodically attempts to reconnect to missing peers
    fn start_reconnect_mechanism(
        config: &config::Config,
        incoming_tx: mpsc::Sender<Incoming<M>>,
        peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<M>>>>,
        peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
        target_peers: Arc<RwLock<HashSet<SocketAddr>>>,
    ) {
        // Clone configuration values to avoid moving references into the task
        let retry_interval = Duration::from_secs(5); // Retry every 5 seconds
        let node_id = config.node.id;
        let peers_to_connect = config.peers.clone();
        
        tokio::spawn(async move {
            // Build a map of peer IDs to addresses for peers with lower IDs
            let mut lower_id_peers = HashMap::new();
            for peer in &peers_to_connect {
                if peer.id < node_id {
                    lower_id_peers.insert(peer.id, peer.address);
                }
            }
            
            loop {
                // Wait before attempting reconnections
                tokio::time::sleep(retry_interval).await;
                
                // Identify peers that should be connected but aren't
                let peers_read = peers.read().await;
                
                // Only try to reconnect to peers with lower IDs (to avoid duplicate connections)
                let missing_peers: Vec<SocketAddr> = lower_id_peers
                    .values()
                    .filter(|addr| !peers_read.contains_key(addr))
                    .cloned()
                    .collect();
                
                drop(peers_read);
                
                // Attempt to connect to missing peers
                for peer_addr in missing_peers {
                    let peers_clone = peers.clone();
                    let peers_id_clone = peers_id.clone();
                    let incoming_tx_clone = incoming_tx.clone();
                    
                    match handlers::connect(peer_addr, incoming_tx_clone, peers_clone, peers_id_clone).await {
                        Ok(_) => println!("Reconnected to peer: {}", peer_addr),
                        Err(e) => {
                            if cfg!(debug_assertions) {
                                eprintln!("Failed to reconnect to peer {}: {}", peer_addr, e);
                            }
                        }
                    }
                }
            }
        });
    }

    /// Spawn a task to handle incoming connections
    fn handle_incoming_connections(
        listener: TcpListener,
        incoming_tx: mpsc::Sender<Incoming<M>>,
        peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<M>>>>,
        peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
    ) {
        tokio::spawn(async move {
            while let Ok((stream, address)) = listener.accept().await {
                println!("Incoming connection from: {}", address);
                let peers_clone = peers.clone();
                let peers_id_clone = peers_id.clone();
                let incoming_tx_clone = incoming_tx.clone();
                
                tokio::spawn(async move {
                    handlers::handle_connection(
                        stream,
                        address,
                        incoming_tx_clone,
                        peers_clone,
                        peers_id_clone,
                    )
                    .await;
                });
            }
        });
    }

    /// Connect to peers with lower IDs to avoid duplicate connections
    fn connect_to_peers(
        config: &config::Config,
        incoming_tx: mpsc::Sender<Incoming<M>>,
        peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<M>>>>,
        peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
    ) {
        // Clone the important values from config rather than the reference itself
        let node_id = config.node.id;
        let peers_to_connect = config.peers.clone();
        
        tokio::spawn(async move {
            for peer in peers_to_connect.iter() {
                // Only initiate connections to peers with lower IDs
                // to avoid duplicate connections
                if peer.id < node_id {
                    let peers_clone = peers.clone();
                    let peers_id_clone = peers_id.clone();
                    let incoming_tx_clone = incoming_tx.clone();
                    
                    match handlers::connect(peer.address, incoming_tx_clone, peers_clone, peers_id_clone).await {
                        Ok(_) => println!("Connected to peer: {}", peer.address),
                        Err(e) => eprintln!("Error connecting to peer {}: {}", peer.address, e),
                    }
                } else {
                    println!("Waiting for peer with higher ID to initiate connection: {}", peer.address);
                }
            }
        });
    }

    /// Handle outgoing messages
    fn handle_outgoing_messages(
        mut outgoing_rx: mpsc::Receiver<Outgoing<M>>,
        peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<M>>>>,
        peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
    ) {
        tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.next().await {
                if let Err(e) = handlers::handle_outgoing(msg, &peers, &peers_id).await {
                    eprintln!("Error sending message: {}", e);
                }
            }
        });
    }
}
