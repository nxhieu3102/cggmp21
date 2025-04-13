use std::net::{SocketAddr, ToSocketAddrs};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use futures::{Stream, StreamExt, FutureExt};
use futures_channel::{mpsc, oneshot};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc as tokio_mpsc;
use tokio::task;
use tracing::{info, error, debug};
use crate::message::Message;
use crate::transport::TransportAdapter;

/// Error type for TCP transport
#[derive(Debug, thiserror::Error)]
pub enum TcpError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Channel error: {0}")]
    ChannelError(String),
    
    #[error("Connection error: {0}")]
    ConnectionError(String),
}

/// TCP-based implementation of TransportAdapter
#[derive(Debug)]
pub struct TcpTransportAdapter<M: Message> {
    /// The address to bind to
    bind_address: String,
    
    /// Connected peers
    peers: Arc<Mutex<HashMap<String, SocketAddr>>>,
    
    /// Active connections
    connections: Arc<Mutex<HashMap<String, tokio_mpsc::Sender<Vec<u8>>>>>,
    
    /// Channel for incoming messages
    incoming_tx: Arc<Mutex<Option<mpsc::Sender<(String, Vec<u8>)>>>>,
    
    /// Channel for outgoing messages
    outgoing_tx: mpsc::Sender<(String, Vec<u8>)>,
    
    /// Receiver for outgoing messages
    outgoing_rx: Arc<Mutex<Option<mpsc::Receiver<(String, Vec<u8>)>>>>,
    
    /// Phantom data for the message type
    _marker: std::marker::PhantomData<M>,
}

impl<M: Message> TcpTransportAdapter<M> {
    /// Create a new TCP transport adapter
    pub fn new(bind_address: &str) -> Self {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(100);
        
        Self {
            bind_address: bind_address.to_string(),
            peers: Arc::new(Mutex::new(HashMap::new())),
            connections: Arc::new(Mutex::new(HashMap::new())),
            incoming_tx: Arc::new(Mutex::new(None)),
            outgoing_tx,
            outgoing_rx: Arc::new(Mutex::new(Some(outgoing_rx))),
            _marker: std::marker::PhantomData,
        }
    }
    
    /// Handle an incoming connection
    async fn handle_connection(
        stream: TcpStream, 
        addr: SocketAddr,
        peer_id: String,
        connections: Arc<Mutex<HashMap<String, tokio_mpsc::Sender<Vec<u8>>>>>,
        incoming_tx: mpsc::Sender<(String, Vec<u8>)>,
    ) -> Result<(), TcpError> {
        let (mut read, mut write) = stream.into_split();
        
        // Channel for sending messages to the write half
        let (tx, mut rx) = tokio_mpsc::channel::<Vec<u8>>(100);
        
        // Store the sender in connections
        {
            let mut connections = connections.lock().unwrap();
            connections.insert(peer_id.clone(), tx);
        }
        
        // Read task
        let incoming_tx_clone = incoming_tx.clone();
        let peer_id_clone = peer_id.clone();
        let read_task = task::spawn(async move {
            let mut buffer = [0u8; 4096];
            
            loop {
                match read.read(&mut buffer).await {
                    Ok(0) => {
                        // Connection closed
                        debug!("Connection closed by peer: {}", peer_id_clone);
                        break;
                    }
                    Ok(n) => {
                        // Got some data, forward it
                        let message_data = buffer[0..n].to_vec();
                        let _ = incoming_tx_clone
                            .clone()
                            .try_send((peer_id_clone.clone(), message_data))
                            .map_err(|e| {
                                error!("Failed to forward message: {}", e);
                            });
                    }
                    Err(e) => {
                        // Error reading
                        error!("Error reading from {}: {}", peer_id_clone, e);
                        break;
                    }
                }
            }
            
            // Remove connection when done
            let connections_clone = connections.clone();
            let peer_id_clone = peer_id_clone.clone();
            task::spawn(async move {
                let mut connections = connections_clone.lock().unwrap();
                connections.remove(&peer_id_clone);
                debug!("Removed connection for peer: {}", peer_id_clone);
            });
        });
        
        // Write task
        let write_task = task::spawn(async move {
            while let Some(data) = rx.recv().await {
                if let Err(e) = write.write_all(&data).await {
                    error!("Error writing to {}: {}", peer_id, e);
                    break;
                }
            }
            debug!("Write task for peer {} finished", peer_id);
        });
        
        // Wait for either task to finish
        tokio::select! {
            _ = read_task => {},
            _ = write_task => {},
        }
        
        Ok(())
    }
}

impl<M: Message> TransportAdapter for TcpTransportAdapter<M> {
    type MessageType = M;
    type ErrorType = TcpError;
    
    fn initialize(&mut self) -> Result<(), Self::ErrorType> {
        // Create new channel for incoming messages
        let (tx, rx) = mpsc::channel(100);
        
        // Store sender and return receiver to be used by incoming_raw
        *self.incoming_tx.lock().unwrap() = Some(tx);
        
        Ok(())
    }
    
    fn connect(&mut self, address: &str) -> Result<String, Self::ErrorType> {
        // Try to parse the address
        let socket_addr = address.to_socket_addrs()
            .map_err(|e| TcpError::InvalidAddress(format!("Invalid address {}: {}", address, e)))?
            .next()
            .ok_or_else(|| TcpError::InvalidAddress(format!("Could not resolve address: {}", address)))?;
        
        // Generate a peer ID
        let peer_id = format!("tcp-{}", socket_addr);
        
        // Store the peer
        {
            let mut peers = self.peers.lock().unwrap();
            peers.insert(peer_id.clone(), socket_addr);
        }
        
        // Get the incoming sender
        let incoming_tx = match self.incoming_tx.lock().unwrap().as_ref() {
            Some(tx) => tx.clone(),
            None => return Err(TcpError::ConnectionError("Transport not initialized".into())),
        };
        
        // Clone necessary references for the async task
        let peer_id_clone = peer_id.clone();
        let connections = self.connections.clone();
        
        // Connect using tokio
        task::spawn(async move {
            match TcpStream::connect(socket_addr).await {
                Ok(stream) => {
                    info!("Connected to peer: {}", socket_addr);
                    if let Err(e) = Self::handle_connection(
                        stream, 
                        socket_addr, 
                        peer_id_clone.clone(), 
                        connections, 
                        incoming_tx
                    ).await {
                        error!("Error handling connection to {}: {}", peer_id_clone, e);
                    }
                }
                Err(e) => {
                    error!("Failed to connect to {}: {}", socket_addr, e);
                }
            }
        });
        
        Ok(peer_id)
    }
    
    fn disconnect(&mut self, peer_id: &str) -> Result<(), Self::ErrorType> {
        // Remove the peer from the list
        let found = {
            let mut peers = self.peers.lock().unwrap();
            peers.remove(peer_id).is_some()
        };
        
        // Remove the connection
        {
            let mut connections = self.connections.lock().unwrap();
            connections.remove(peer_id);
        }
        
        if found {
            Ok(())
        } else {
            Err(TcpError::ConnectionError(format!("Peer {} not found", peer_id)))
        }
    }
    
    fn send_raw(&self, peer_id: &str, data: &[u8]) -> Result<(), Self::ErrorType> {
        let sender = {
            let connections = self.connections.lock().unwrap();
            connections.get(peer_id).cloned()
        };
        
        match sender {
            Some(tx) => {
                // Clone the data to avoid lifetime issues
                let data_vec = data.to_vec();
                let peer_id_owned = peer_id.to_string();
                
                // Use a blocking executor to send the message
                std::thread::spawn(move || {
                    if let Err(e) = tx.blocking_send(data_vec) {
                        error!("Failed to send message to {}: {}", peer_id_owned, e);
                    }
                });
                Ok(())
            }
            None => Err(TcpError::ConnectionError(format!("Peer {} not connected", peer_id))),
        }
    }
    
    fn incoming_raw(&self) -> Box<dyn Stream<Item = (String, Vec<u8>)> + Unpin + Send> {
        let (tx, rx) = mpsc::channel(100);
        
        if let Some(tx_clone) = {
            let mut incoming_tx = self.incoming_tx.lock().unwrap();
            incoming_tx.replace(tx)
        } {
            // Create a channel for signaling exit
            let (exit_tx, exit_rx) = oneshot::channel::<()>();
            
            // Store the exit sender in a shared container
            let running = Arc::new(Mutex::new(Some(exit_tx)));
            
            // Spawn a task to forward messages to the returned channel
            tokio::task::spawn(async move {
                // We're using a placeholder task here just to demonstrate the cleanup
                // In a real implementation, you would handle incoming messages
                
                // Wait for the exit signal
                let _ = exit_rx.await;
                
                // When exit signal received, we terminate the task
                debug!("Incoming raw stream task terminated");
            });
            
            // Return a stream that, when dropped, will clean up the task
            let rx_with_cleanup = futures::stream::unfold((rx, running), move |(mut rx, running)| {
                Box::pin(async move {
                    match rx.next().await {
                        Some(item) => Some((item, (rx, running))),
                        None => {
                            // If the stream ends, make sure to clean up
                            if let Some(exit_tx) = running.lock().unwrap().take() {
                                let _ = exit_tx.send(());
                            }
                            None
                        }
                    }
                })
            });
            
            Box::new(rx_with_cleanup)
        } else {
            // We don't have an incoming sender, so the stream will be empty
            Box::new(rx)
        }
    }
    
    fn outgoing_channel(&self) -> mpsc::Sender<(String, Vec<u8>)> {
        self.outgoing_tx.clone()
    }
    
    fn connected_peers(&self) -> Vec<String> {
        let peers = self.peers.lock().unwrap();
        peers.keys().cloned().collect()
    }
    
    fn start(&mut self) -> Result<(), Self::ErrorType> {
        // Initialize
        self.initialize()?;
        
        // Get the address to bind to
        let addr = self.bind_address.clone();
        let socket_addr = addr.to_socket_addrs()
            .map_err(|e| TcpError::InvalidAddress(format!("Invalid bind address {}: {}", addr, e)))?
            .next()
            .ok_or_else(|| TcpError::InvalidAddress(format!("Could not resolve bind address: {}", addr)))?;
        
        // Get the outgoing receiver
        let mut outgoing_rx = self.outgoing_rx.lock().unwrap().take()
            .ok_or_else(|| TcpError::ConnectionError("Outgoing receiver already taken".into()))?;
        
        // Get the incoming sender
        let incoming_tx = match self.incoming_tx.lock().unwrap().as_ref() {
            Some(tx) => tx.clone(),
            None => return Err(TcpError::ConnectionError("Transport not initialized".into())),
        };
        
        // Clone necessary references
        let connections_clone = self.connections.clone();
        let peers = self.peers.clone();
        
        // Spawn listener task
        let incoming_tx_clone = incoming_tx.clone();
        let connections_clone2 = connections_clone.clone();
        
        task::spawn(async move {
            // Start TCP listener
            match TcpListener::bind(socket_addr).await {
                Ok(listener) => {
                    info!("Listening on {}", socket_addr);
                    
                    // Accept connections
                    loop {
                        match listener.accept().await {
                            Ok((stream, addr)) => {
                                info!("Accepted connection from: {}", addr);
                                
                                // Generate a peer ID
                                let peer_id = format!("tcp-{}", addr);
                                
                                // Store the peer
                                {
                                    let mut peers = peers.lock().unwrap();
                                    peers.insert(peer_id.clone(), addr);
                                }
                                
                                // Clone everything needed for the connection handler
                                let connections_clone3 = connections_clone2.clone();
                                let incoming_tx_clone2 = incoming_tx_clone.clone();
                                let peer_id_clone = peer_id.clone();
                                
                                // Handle the connection
                                task::spawn(async move {
                                    if let Err(e) = TcpTransportAdapter::<M>::handle_connection(
                                        stream, 
                                        addr, 
                                        peer_id_clone.clone(), 
                                        connections_clone3, 
                                        incoming_tx_clone2
                                    ).await {
                                        error!("Error handling connection from {}: {}", peer_id_clone, e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Error accepting connection: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind to {}: {}", socket_addr, e);
                }
            }
        });
        
        // Spawn task to process outgoing messages
        let peers_clone = self.peers.clone();
        let connections_clone3 = connections_clone.clone();
        let incoming_tx_clone3 = incoming_tx.clone();
        
        task::spawn(async move {
            while let Some((peer_id, data)) = outgoing_rx.next().await {
                // Check if peer exists
                let peer_addr = {
                    let peers = peers_clone.lock().unwrap();
                    peers.get(&peer_id).cloned()
                };
                
                if let Some(addr) = peer_addr {
                    // Try to connect if not already connected
                    if !connections_clone3.lock().unwrap().contains_key(&peer_id) {
                        match TcpStream::connect(addr).await {
                            Ok(stream) => {
                                info!("Connected to peer for outgoing message: {}", addr);
                                let connections_clone4 = connections_clone3.clone();
                                let incoming_tx_clone4 = incoming_tx_clone3.clone();
                                let peer_id_clone = peer_id.clone();
                                
                                task::spawn(async move {
                                    if let Err(e) = TcpTransportAdapter::<M>::handle_connection(
                                        stream, 
                                        addr, 
                                        peer_id_clone.clone(), 
                                        connections_clone4, 
                                        incoming_tx_clone4
                                    ).await {
                                        error!("Error handling connection for outgoing message to {}: {}", peer_id_clone, e);
                                    }
                                });
                                
                                // Wait a bit for the connection to be established
                                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                            }
                            Err(e) => {
                                error!("Failed to connect to {} for outgoing message: {}", addr, e);
                                continue;
                            }
                        }
                    }
                    
                    // Get the sender
                    let sender = {
                        let connections = connections_clone3.lock().unwrap();
                        connections.get(&peer_id).cloned()
                    };
                    
                    // Send the data
                    if let Some(tx) = sender {
                        if let Err(e) = tx.send(data).await {
                            error!("Failed to send outgoing message to {}: {}", peer_id, e);
                        }
                    } else {
                        error!("No connection found for peer {} when sending outgoing message", peer_id);
                    }
                } else {
                    error!("Unknown peer {} for outgoing message", peer_id);
                }
            }
        });
        
        Ok(())
    }
    
    fn stop(&mut self) -> Result<(), Self::ErrorType> {
        // Close all connections
        let peer_ids: Vec<String> = {
            let peers = self.peers.lock().unwrap();
            peers.keys().cloned().collect()
        };
        
        for peer_id in peer_ids {
            let _ = self.disconnect(&peer_id);
        }
        
        Ok(())
    }
} 
