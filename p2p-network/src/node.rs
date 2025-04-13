use crate::network::NetworkLayer;
use crate::handler::MessageHandler;
use crate::message::Message;
use crate::key::KeyManager;
use crate::config::ConfigLoader;
use std::fmt::Debug;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use futures::{Stream, StreamExt};
use futures_channel::mpsc;
use std::marker::PhantomData;

/// Errors that can occur in the Node operations
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    #[error("Message handling error: {0}")]
    MessageError(String),
    
    #[error("Node is not started")]
    NotStarted,
}

/// Connection status for a peer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Connection is being established
    Connecting,
    
    /// Connection is established and ready for communication
    Connected,
    
    /// Connection is being closed
    Disconnecting,
    
    /// Connection is closed
    Disconnected,
    
    /// Connection failed
    Failed(String),
}

/// Information about a peer connection
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The unique identifier of the peer
    pub id: String,
    
    /// The address or connection string for the peer
    pub address: String,
    
    /// The current connection status
    pub status: ConnectionStatus,
    
    /// When the connection was established
    pub connected_at: Option<u64>,
    
    /// Additional metadata about the peer
    pub metadata: HashMap<String, String>,
}

/// Abstracted node representation independent of transport mechanism
#[derive(Debug)]
pub struct Node<N, K, C, H, M>
where
    N: NetworkLayer<MessageType = M>,
    K: KeyManager,
    C: ConfigLoader,
    H: MessageHandler<MessageType = M> + Clone + 'static,
    M: Message,
{
    /// The unique identifier of this node
    pub id: Option<String>,
    
    /// The network layer for communication
    network: N,
    
    /// The key manager for cryptographic operations
    key_manager: K,
    
    /// The configuration loader
    config: C,
    
    /// The message handler
    handler: H,
    
    /// Connected peers information
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    
    /// Whether the node is running
    running: Arc<Mutex<bool>>,
    
    /// Event channel for node events
    event_tx: mpsc::Sender<NodeEvent<M>>,
    
    /// Event channel receiver
    event_rx: Arc<Mutex<Option<mpsc::Receiver<NodeEvent<M>>>>>,
    
    /// Phantom data for message type
    _message_type: PhantomData<M>,
}

/// Events emitted by the node
#[derive(Debug, Clone)]
pub enum NodeEvent<M: Message> {
    /// A peer connected
    PeerConnected { peer_id: String },
    
    /// A peer disconnected
    PeerDisconnected { peer_id: String, reason: Option<String> },
    
    /// A message was received from a peer
    MessageReceived { peer_id: String, message: M },
    
    /// A message was sent to a peer
    MessageSent { peer_id: String, message: M },
    
    /// A connection attempt failed
    ConnectionFailed { address: String, error: String },
    
    /// The node was started
    Started,
    
    /// The node was stopped
    Stopped,
    
    /// An error occurred
    Error { context: String, error: String },
}

impl<N, K, C, H, M> Node<N, K, C, H, M>
where
    N: NetworkLayer<MessageType = M>,
    K: KeyManager,
    C: ConfigLoader,
    H: MessageHandler<MessageType = M> + Clone + 'static,
    M: Message,
{
    /// Create a new node with the provided components
    pub fn new(id: String, network: N, key_manager: K, config: C, handler: H) -> Self {
        let (event_tx, event_rx) = mpsc::channel(100);
        
        Self {
            id: Some(id),
            network,
            key_manager,
            config,
            handler,
            peers: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(Mutex::new(false)),
            event_tx,
            event_rx: Arc::new(Mutex::new(Some(event_rx))),
            _message_type: PhantomData,
        }
    }
    
    /// Start the node
    pub fn start(&mut self) -> Result<(), NodeError> {
        // Check if already running
        {
            let mut running = self.running.lock().unwrap();
            if *running {
                return Ok(());
            }
            *running = true;
        }
        
        // Initialize the network layer
        self.network.start().map_err(|e| {
            NodeError::NetworkError(format!("Failed to start network layer: {}", e))
        })?;
        
        // Emit started event
        let mut event_tx = self.event_tx.clone();
        let _ = event_tx.try_send(NodeEvent::Started);
        
        // Start message processing
        self.process_messages()?;
        
        Ok(())
    }
    
    /// Stop the node
    pub fn stop(&mut self) -> Result<(), NodeError> {
        // Check if already stopped
        {
            let mut running = self.running.lock().unwrap();
            if !*running {
                return Ok(());
            }
            *running = false;
        }
        
        // Stop the network layer
        self.network.stop().map_err(|e| {
            NodeError::NetworkError(format!("Failed to stop network layer: {}", e))
        })?;
        
        // Emit stopped event
        let mut event_tx = self.event_tx.clone();
        let _ = event_tx.try_send(NodeEvent::Stopped);
        
        Ok(())
    }
    
    /// Connect to a peer using the given address
    pub fn connect(&mut self, address: &str) -> Result<String, NodeError> {
        // Check if node is running
        {
            let running = self.running.lock().unwrap();
            if !*running {
                return Err(NodeError::NotStarted);
            }
        }
        
        // Connect to the peer
        self.network.connect(address).map_err(|e| {
            NodeError::ConnectionError(format!("Failed to connect to {}: {}", address, e))
        })?;
        
        // Generate a peer ID based on the address
        let peer_id = format!("peer-{}", address);
        
        // Update peer info
        {
            let mut peers = self.peers.lock().unwrap();
            let now = get_timestamp();
            
            peers.insert(peer_id.clone(), PeerInfo {
                id: peer_id.clone(),
                address: address.to_string(),
                status: ConnectionStatus::Connected,
                connected_at: Some(now),
                metadata: HashMap::new(),
            });
        }
        
        // Notify handler about the new connection
        let _ = self.handler.on_peer_connected(&peer_id).map_err(|e| {
            NodeError::MessageError(format!("Handler error on peer connection: {}", e))
        });
        
        // Emit event
        let mut event_tx = self.event_tx.clone();
        let _ = event_tx.try_send(NodeEvent::PeerConnected {
            peer_id: peer_id.clone(),
        });
        
        Ok(peer_id)
    }
    
    /// Disconnect from a peer
    pub fn disconnect(&mut self, peer_id: &str) -> Result<(), NodeError> {
        // Check if node is running
        {
            let running = self.running.lock().unwrap();
            if !*running {
                return Err(NodeError::NotStarted);
            }
        }
        
        // Update peer status before disconnecting
        {
            let mut peers = self.peers.lock().unwrap();
            if let Some(peer_info) = peers.get_mut(peer_id) {
                peer_info.status = ConnectionStatus::Disconnecting;
            }
        }
        
        // Disconnect from the peer
        self.network.disconnect(peer_id).map_err(|e| {
            NodeError::ConnectionError(format!("Failed to disconnect from {}: {}", peer_id, e))
        })?;
        
        // Update peer info
        {
            let mut peers = self.peers.lock().unwrap();
            if let Some(peer_info) = peers.get_mut(peer_id) {
                peer_info.status = ConnectionStatus::Disconnected;
                peer_info.connected_at = None;
            }
        }
        
        // Notify handler about the disconnection
        let _ = self.handler.on_peer_disconnected(peer_id).map_err(|e| {
            NodeError::MessageError(format!("Handler error on peer disconnection: {}", e))
        });
        
        // Emit event
        let mut event_tx = self.event_tx.clone();
        let _ = event_tx.try_send(NodeEvent::PeerDisconnected {
            peer_id: peer_id.to_string(),
            reason: None,
        });
        
        Ok(())
    }
    
    /// Send a message to a specific peer
    pub fn send_to(&self, peer_id: &str, message: M) -> Result<(), NodeError> {
        // Check if node is running
        {
            let running = self.running.lock().unwrap();
            if !*running {
                return Err(NodeError::NotStarted);
            }
        }
        
        // Check if peer is connected
        {
            let peers = self.peers.lock().unwrap();
            if let Some(peer_info) = peers.get(peer_id) {
                if peer_info.status != ConnectionStatus::Connected {
                    return Err(NodeError::ConnectionError(
                        format!("Peer {} is not connected", peer_id)
                    ));
                }
            } else {
                return Err(NodeError::ConnectionError(
                    format!("Unknown peer {}", peer_id)
                ));
            }
        }
        
        // Process the message with the handler
        let processed_message = self.handler.process_outgoing(peer_id, message.clone()).map_err(|e| {
            NodeError::MessageError(format!("Failed to process outgoing message: {}", e))
        })?;
        
        // Send the message
        self.network.send_to(peer_id, processed_message).map_err(|e| {
            NodeError::NetworkError(format!("Failed to send message to {}: {}", peer_id, e))
        })?;
        
        // Emit event
        let mut event_tx = self.event_tx.clone();
        let _ = event_tx.try_send(NodeEvent::MessageSent {
            peer_id: peer_id.to_string(),
            message,
        });
        
        Ok(())
    }
    
    /// Broadcast a message to all connected peers
    pub fn broadcast(&self, message: M) -> Result<(), NodeError> {
        // Check if node is running
        {
            let running = self.running.lock().unwrap();
            if !*running {
                return Err(NodeError::NotStarted);
            }
        }
        
        // Get list of connected peers
        let connected_peers: Vec<String> = {
            let peers = self.peers.lock().unwrap();
            peers.iter()
                .filter(|(_, info)| info.status == ConnectionStatus::Connected)
                .map(|(id, _)| id.clone())
                .collect()
        };
        
        // Send the message to each connected peer
        for peer_id in connected_peers {
            let _ = self.send_to(&peer_id, message.clone());
        }
        
        Ok(())
    }
    
    /// Get a list of connected peers
    pub fn connected_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.lock().unwrap();
        peers.values().cloned().collect()
    }
    
    /// Get a reference to the network layer
    pub fn network(&self) -> &N {
        &self.network
    }
    
    /// Get a mutable reference to the network layer
    pub fn network_mut(&mut self) -> &mut N {
        &mut self.network
    }
    
    /// Get a reference to the key manager
    pub fn key_manager(&self) -> &K {
        &self.key_manager
    }
    
    /// Get a reference to the config loader
    pub fn config(&self) -> &C {
        &self.config
    }
    
    /// Get a reference to the message handler
    pub fn handler(&self) -> &H {
        &self.handler
    }
    
    /// Get the event stream for node events
    pub fn events(&self) -> Option<impl Stream<Item = NodeEvent<M>>> {
        let mut rx_lock = self.event_rx.lock().unwrap();
        rx_lock.take()
    }
    
    /// Process incoming messages
    fn process_messages(&self) -> Result<(), NodeError> {
        // Check if node is running
        {
            let running = self.running.lock().unwrap();
            if !*running {
                return Err(NodeError::NotStarted);
            }
        }
        
        // Get stream of incoming messages
        let mut incoming = self.network.incoming_messages();
        let running = self.running.clone();
        
        // Create a clone of the handler to avoid self reference in the thread
        let handler_clone = Arc::new(
            self.handler.clone()
        );
        
        let mut event_tx = self.event_tx.clone();
        let peers = self.peers.clone();
        
        // Create clones for both code paths upfront to avoid moved value errors
        let handler_clone_native = handler_clone.clone();
        let handler_clone_wasm = handler_clone.clone();
        
        // Process messages in a separate thread/task
        #[cfg(feature = "native")]
        {
            use std::thread;
            thread::spawn(move || {
                while let Some((peer_id, message)) = futures::executor::block_on(incoming.next()) {
                    // Check if still running
                    {
                        let running_guard = running.lock().unwrap();
                        if !*running_guard {
                            break;
                        }
                    }
                    
                    // Update peer info to ensure it's in our list
                    {
                        let mut peers_guard = peers.lock().unwrap();
                        if !peers_guard.contains_key(&peer_id) {
                            peers_guard.insert(peer_id.clone(), PeerInfo {
                                id: peer_id.clone(),
                                address: "unknown".to_string(),
                                status: ConnectionStatus::Connected,
                                connected_at: Some(get_timestamp()),
                                metadata: HashMap::new(),
                            });
                            
                            // Emit peer connected event for newly discovered peers
                            let _ = event_tx.try_send(NodeEvent::PeerConnected {
                                peer_id: peer_id.clone(),
                            });
                        }
                    }
                    
                    // Handle the message
                    if let Err(e) = handler_clone_native.handle_incoming(&peer_id, message.clone()) {
                        let _ = event_tx.try_send(NodeEvent::Error {
                            context: format!("Failed to handle message from {}", peer_id),
                            error: e.to_string(),
                        });
                    } else {
                        // Emit message received event on success
                        let _ = event_tx.try_send(NodeEvent::MessageReceived {
                            peer_id: peer_id.clone(),
                            message,
                        });
                    }
                }
            });
        }
        
        // For WASM targets, we need to use a different approach
        #[cfg(feature = "wasm")]
        {
            use wasm_bindgen_futures::spawn_local;
            
            // Create new clones for the WASM context to avoid "value used after move" errors
            let mut incoming_wasm = self.network.incoming_messages();
            let running_wasm = self.running.clone(); 
            let mut event_tx_wasm = self.event_tx.clone();
            let peers_wasm = self.peers.clone();
            
            spawn_local(async move {
                while let Some((peer_id, message)) = incoming_wasm.next().await {
                    // Check if still running
                    {
                        let running_guard = running_wasm.lock().unwrap();
                        if !*running_guard {
                            break;
                        }
                    }
                    
                    // Update peer info to ensure it's in our list
                    {
                        let mut peers_guard = peers_wasm.lock().unwrap();
                        if !peers_guard.contains_key(&peer_id) {
                            peers_guard.insert(peer_id.clone(), PeerInfo {
                                id: peer_id.clone(),
                                address: "unknown".to_string(),
                                status: ConnectionStatus::Connected,
                                connected_at: Some(get_timestamp()),
                                metadata: HashMap::new(),
                            });
                            
                            // Emit peer connected event for newly discovered peers
                            let _ = event_tx_wasm.try_send(NodeEvent::PeerConnected {
                                peer_id: peer_id.clone(),
                            });
                        }
                    }
                    
                    // Handle the message
                    if let Err(e) = handler_clone_wasm.handle_incoming(&peer_id, message.clone()) {
                        let _ = event_tx_wasm.try_send(NodeEvent::Error {
                            context: format!("Failed to handle message from {}", peer_id),
                            error: e.to_string(),
                        });
                    } else {
                        // Emit message received event on success
                        let _ = event_tx_wasm.try_send(NodeEvent::MessageReceived {
                            peer_id: peer_id.clone(),
                            message,
                        });
                    }
                }
            });
        }
        
        Ok(())
    }
}

/// Fluent interface for node configuration
#[derive(Default)]
pub struct NodeBuilder<N, K, C, H, M>
where
    M: Message,
    N: NetworkLayer<MessageType = M>,
    H: MessageHandler<MessageType = M> + Clone + 'static,
{
    id: Option<String>,
    network: Option<N>,
    key_manager: Option<K>,
    config: Option<C>,
    handler: Option<H>,
    _message_type: PhantomData<M>,
}

impl<N, K, C, H, M> NodeBuilder<N, K, C, H, M>
where
    M: Message,
    N: NetworkLayer<MessageType = M>,
    H: MessageHandler<MessageType = M> + Clone + 'static,
{
    /// Create a new node builder
    pub fn new() -> Self {
        Self {
            id: None,
            network: None,
            key_manager: None,
            config: None,
            handler: None,
            _message_type: PhantomData,
        }
    }
    
    /// Set the node ID
    pub fn with_id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }
    
    /// Set the network layer
    pub fn with_network(mut self, network: N) -> Self {
        self.network = Some(network);
        self
    }
    
    /// Set the key manager
    pub fn with_key_manager(mut self, key_manager: K) -> Self {
        self.key_manager = Some(key_manager);
        self
    }
    
    /// Set the config loader
    pub fn with_config(mut self, config: C) -> Self {
        self.config = Some(config);
        self
    }
    
    /// Set the message handler
    pub fn with_handler(mut self, handler: H) -> Self {
        self.handler = Some(handler);
        self
    }
    
    /// Build the node
    pub fn build(self) -> Result<Node<N, K, C, H, M>, NodeError> 
    where
        N: NetworkLayer<MessageType = M>,
        K: KeyManager,
        C: ConfigLoader,
        H: MessageHandler<MessageType = M> + Clone + 'static,
        M: Message,
    {
        let id = self.id.ok_or(NodeError::ConfigError("Node ID not set".into()))?;
        let network = self.network.ok_or(NodeError::ConfigError("Network layer not set".into()))?;
        let key_manager = self.key_manager.ok_or(NodeError::ConfigError("Key manager not set".into()))?;
        let config = self.config.ok_or(NodeError::ConfigError("Config loader not set".into()))?;
        let handler = self.handler.ok_or(NodeError::ConfigError("Message handler not set".into()))?;
        
        Ok(Node::new(id, network, key_manager, config, handler))
    }
}

/// Get current timestamp in seconds, compatible with both native and WASM environments
#[cfg(not(target_arch = "wasm32"))]
fn get_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(target_arch = "wasm32")]
fn get_timestamp() -> u64 {
    use wasm_bindgen::prelude::*;
    
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = Date)]
        fn now() -> f64;
    }
    
    // JavaScript Date.now() returns milliseconds, so divide by 1000 to get seconds
    (now() / 1000.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{MockNetworkLayer, MockKeyManager, MockConfigLoader, MockMessageHandler};
    use crate::message::InternalMessage;

    #[test]
    fn test_node_creation() {
        let network = MockNetworkLayer::<InternalMessage>::new();
        let key_manager = MockKeyManager::new();
        let config = MockConfigLoader::new();
        let handler = MockMessageHandler::<InternalMessage>::new();
        
        let node = Node::new(
            "test-node".to_string(),
            network,
            key_manager,
            config,
            handler,
        );
        
        assert_eq!(node.id, Some("test-node".to_string()));
    }
    
    #[test]
    fn test_node_builder() {
        let network = MockNetworkLayer::<InternalMessage>::new();
        let key_manager = MockKeyManager::new();
        let config = MockConfigLoader::new();
        let handler = MockMessageHandler::<InternalMessage>::new();
        
        let node = NodeBuilder::<_, _, _, _, InternalMessage>::new()
            .with_id("test-node".to_string())
            .with_network(network)
            .with_key_manager(key_manager)
            .with_config(config)
            .with_handler(handler)
            .build();
            
        assert!(node.is_ok());
        assert_eq!(node.unwrap().id, Some("test-node".to_string()));
    }
    
    #[test]
    fn test_node_builder_missing_components() {
        let node = NodeBuilder::<
            MockNetworkLayer<InternalMessage>, 
            MockKeyManager, 
            MockConfigLoader, 
            MockMessageHandler<InternalMessage>, 
            InternalMessage
        >::new()
            .build();
            
        assert!(node.is_err());
    }
}

// Implement MessageHandler for Node
impl<N, K, C, H, M> MessageHandler for Node<N, K, C, H, M>
where
    N: NetworkLayer<MessageType = M>,
    K: KeyManager,
    C: ConfigLoader,
    H: MessageHandler<MessageType = M> + Clone + 'static,
    M: Message,
{
    type MessageType = M;
    type ErrorType = NodeError;

    fn handle_incoming(&self, peer_id: &str, message: Self::MessageType) -> Result<(), Self::ErrorType> {
        self.handler.handle_incoming(peer_id, message).map_err(|e| {
            NodeError::MessageError(format!("Failed to handle incoming message: {}", e))
        })
    }

    fn process_outgoing(&self, peer_id: &str, message: Self::MessageType) -> Result<Self::MessageType, Self::ErrorType> {
        self.handler.process_outgoing(peer_id, message).map_err(|e| {
            NodeError::MessageError(format!("Failed to process outgoing message: {}", e))
        })
    }

    fn on_peer_connected(&self, peer_id: &str) -> Result<(), Self::ErrorType> {
        self.handler.on_peer_connected(peer_id).map_err(|e| {
            NodeError::MessageError(format!("Failed to handle peer connection: {}", e))
        })
    }

    fn on_peer_disconnected(&self, peer_id: &str) -> Result<(), Self::ErrorType> {
        self.handler.on_peer_disconnected(peer_id).map_err(|e| {
            NodeError::MessageError(format!("Failed to handle peer disconnection: {}", e))
        })
    }
} 
