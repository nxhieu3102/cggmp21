/// Mock implementations of the core traits for testing purposes
use crate::handler::MessageHandler;
use crate::transport::TransportAdapter;
use crate::network::NetworkLayer;
use crate::message::{Message, InternalMessage};
use crate::key::KeyManager;
use crate::config::ConfigLoader;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::fmt::Debug;
use std::error::Error;
use futures::Stream;
use futures_channel::mpsc;
use futures::stream::StreamExt;
use futures::SinkExt;
use futures::executor;
use std::marker::PhantomData;

/// Mock error type for testing
#[derive(Debug)]
pub struct MockError {
    message: String,
}

impl std::fmt::Display for MockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MockError: {}", self.message)
    }
}

impl Error for MockError {}

impl MockError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

/// Mock message handler implementation for testing
#[derive(Debug, Clone)]
pub struct MockMessageHandler<M: Message> {
    received_messages: Arc<Mutex<Vec<(String, M)>>>,
    processed_messages: Arc<Mutex<Vec<(String, M)>>>,
    connected_peers: Arc<Mutex<Vec<String>>>,
    disconnected_peers: Arc<Mutex<Vec<String>>>,
    _marker: PhantomData<M>,
}

impl<M: Message> MockMessageHandler<M> {
    pub fn new() -> Self {
        Self {
            received_messages: Arc::new(Mutex::new(Vec::new())),
            processed_messages: Arc::new(Mutex::new(Vec::new())),
            connected_peers: Arc::new(Mutex::new(Vec::new())),
            disconnected_peers: Arc::new(Mutex::new(Vec::new())),
            _marker: PhantomData,
        }
    }
    
    pub fn get_received_messages(&self) -> Vec<(String, M)> {
        self.received_messages.lock().unwrap().clone()
    }
    
    pub fn get_processed_messages(&self) -> Vec<(String, M)> {
        self.processed_messages.lock().unwrap().clone()
    }
    
    pub fn get_connected_peers(&self) -> Vec<String> {
        self.connected_peers.lock().unwrap().clone()
    }
    
    pub fn get_disconnected_peers(&self) -> Vec<String> {
        self.disconnected_peers.lock().unwrap().clone()
    }
}

impl<M: Message> MessageHandler for MockMessageHandler<M> {
    type MessageType = M;
    type ErrorType = MockError;
    
    fn handle_incoming(&self, peer_id: &str, message: Self::MessageType) -> Result<(), Self::ErrorType> {
        self.received_messages.lock().unwrap().push((peer_id.to_string(), message));
        Ok(())
    }
    
    fn process_outgoing(&self, peer_id: &str, message: Self::MessageType) -> Result<Self::MessageType, Self::ErrorType> {
        self.processed_messages.lock().unwrap().push((peer_id.to_string(), message.clone()));
        Ok(message)
    }
    
    fn on_peer_connected(&self, peer_id: &str) -> Result<(), Self::ErrorType> {
        self.connected_peers.lock().unwrap().push(peer_id.to_string());
        Ok(())
    }
    
    fn on_peer_disconnected(&self, peer_id: &str) -> Result<(), Self::ErrorType> {
        self.disconnected_peers.lock().unwrap().push(peer_id.to_string());
        Ok(())
    }
}

/// Mock network layer implementation for testing
#[derive(Debug)]
pub struct MockNetworkLayer<M: Message> {
    peers: Arc<Mutex<HashMap<String, String>>>, // peer_id -> address
    sent_messages: Arc<Mutex<Vec<(String, M)>>>,
    tx: mpsc::Sender<(String, M)>,
    rx: Arc<Mutex<mpsc::Receiver<(String, M)>>>,
    is_running: Arc<Mutex<bool>>,
}

impl<M: Message> MockNetworkLayer<M> {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(100);
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            sent_messages: Arc::new(Mutex::new(Vec::new())),
            tx,
            rx: Arc::new(Mutex::new(rx)),
            is_running: Arc::new(Mutex::new(false)),
        }
    }
    
    pub fn get_sent_messages(&self) -> Vec<(String, M)> {
        self.sent_messages.lock().unwrap().clone()
    }
    
    pub fn simulate_incoming_message(&self, peer_id: &str, message: M) {
        // Clone the sender and send the message
        let mut tx = self.tx.clone();
        executor::block_on(async {
            tx.send((peer_id.to_string(), message)).await.unwrap();
        });
    }
}

impl<M: Message> NetworkLayer for MockNetworkLayer<M> {
    type MessageType = M;
    type ErrorType = MockError;
    
    fn connect(&mut self, peer_address: &str) -> Result<(), Self::ErrorType> {
        if !*self.is_running.lock().unwrap() {
            return Err(MockError::new("Network not started"));
        }
        
        let peer_id = format!("peer-{}", self.peers.lock().unwrap().len());
        self.peers.lock().unwrap().insert(peer_id, peer_address.to_string());
        Ok(())
    }
    
    fn disconnect(&mut self, peer_id: &str) -> Result<(), Self::ErrorType> {
        if !*self.is_running.lock().unwrap() {
            return Err(MockError::new("Network not started"));
        }
        
        if self.peers.lock().unwrap().remove(peer_id).is_some() {
            Ok(())
        } else {
            Err(MockError::new(&format!("Peer {} not found", peer_id)))
        }
    }
    
    fn send_to(&self, peer_id: &str, message: Self::MessageType) -> Result<(), Self::ErrorType> {
        if !*self.is_running.lock().unwrap() {
            return Err(MockError::new("Network not started"));
        }
        
        if self.peers.lock().unwrap().contains_key(peer_id) {
            self.sent_messages.lock().unwrap().push((peer_id.to_string(), message));
            Ok(())
        } else {
            Err(MockError::new(&format!("Peer {} not found", peer_id)))
        }
    }
    
    fn broadcast(&self, message: Self::MessageType) -> Result<(), Self::ErrorType> {
        if !*self.is_running.lock().unwrap() {
            return Err(MockError::new("Network not started"));
        }
        
        let peers: Vec<String> = self.peers.lock().unwrap().keys().cloned().collect();
        for peer_id in peers {
            self.send_to(&peer_id, message.clone())?;
        }
        Ok(())
    }
    
    fn incoming_messages(&self) -> Box<dyn Stream<Item = (String, Self::MessageType)> + Unpin + Send> {
        // Create a new channel for each call to incoming_messages
        let (tx, rx) = mpsc::channel(100);
        
        // Clone the tx for this function
        let mut tx_clone = tx.clone();
        
        // Forward messages from self.rx to the new channel
        let rx_arc = Arc::clone(&self.rx);
        let is_running = Arc::clone(&self.is_running);
        std::thread::spawn(move || {
            let mut rx_guard = rx_arc.lock().unwrap();
            executor::block_on(async {
                while let Some(msg) = rx_guard.next().await {
                    if !*is_running.lock().unwrap() {
                        break;
                    }
                    
                    if tx_clone.send(msg).await.is_err() {
                        break;
                    }
                }
            });
        });
        
        Box::new(rx)
    }
    
    fn outgoing_channel(&self) -> mpsc::Sender<(String, Self::MessageType)> {
        self.tx.clone()
    }
    
    fn connected_peers(&self) -> Vec<String> {
        self.peers.lock().unwrap().keys().cloned().collect()
    }
    
    fn start(&mut self) -> Result<(), Self::ErrorType> {
        let mut running = self.is_running.lock().unwrap();
        if *running {
            return Ok(());
        }
        *running = true;
        Ok(())
    }
    
    fn stop(&mut self) -> Result<(), Self::ErrorType> {
        let mut running = self.is_running.lock().unwrap();
        if !*running {
            return Ok(());
        }
        *running = false;
        Ok(())
    }
}

/// Mock transport adapter implementation for testing
#[derive(Debug)]
pub struct MockTransportAdapter {
    connections: Arc<Mutex<HashMap<String, String>>>, // peer_id -> address
    sent_messages: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    tx: mpsc::Sender<(String, Vec<u8>)>,
    rx: Arc<Mutex<mpsc::Receiver<(String, Vec<u8>)>>>,
}

impl MockTransportAdapter {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(100);
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            sent_messages: Arc::new(Mutex::new(Vec::new())),
            tx,
            rx: Arc::new(Mutex::new(rx)),
        }
    }
    
    pub fn get_sent_messages(&self) -> Vec<(String, Vec<u8>)> {
        self.sent_messages.lock().unwrap().clone()
    }
    
    pub fn simulate_incoming_message(&self, peer_id: &str, data: Vec<u8>) {
        // Clone the sender
        let mut tx = self.tx.clone();
        executor::block_on(async {
            tx.send((peer_id.to_string(), data)).await.unwrap();
        });
    }
}

impl TransportAdapter for MockTransportAdapter {
    type MessageType = InternalMessage;
    type ErrorType = MockError;
    
    fn initialize(&mut self) -> Result<(), Self::ErrorType> {
        Ok(())
    }
    
    fn connect(&mut self, address: &str) -> Result<String, Self::ErrorType> {
        let peer_id = format!("peer-{}", self.connections.lock().unwrap().len());
        self.connections.lock().unwrap().insert(peer_id.clone(), address.to_string());
        Ok(peer_id)
    }
    
    fn disconnect(&mut self, peer_id: &str) -> Result<(), Self::ErrorType> {
        if self.connections.lock().unwrap().remove(peer_id).is_some() {
            Ok(())
        } else {
            Err(MockError::new(&format!("Peer {} not found", peer_id)))
        }
    }
    
    fn send_raw(&self, peer_id: &str, data: &[u8]) -> Result<(), Self::ErrorType> {
        if self.connections.lock().unwrap().contains_key(peer_id) {
            self.sent_messages.lock().unwrap().push((peer_id.to_string(), data.to_vec()));
            Ok(())
        } else {
            Err(MockError::new(&format!("Peer {} not found", peer_id)))
        }
    }
    
    fn incoming_raw(&self) -> Box<dyn Stream<Item = (String, Vec<u8>)> + Unpin + Send> {
        // Create a new channel for each call to incoming_raw
        let (tx, rx) = mpsc::channel(100);
        
        // Clone the tx for this function
        let mut tx_clone = tx.clone();
        
        // Forward messages from self.rx to the new channel
        let rx_arc = Arc::clone(&self.rx);
        std::thread::spawn(move || {
            let mut rx_guard = rx_arc.lock().unwrap();
            executor::block_on(async {
                while let Some(msg) = rx_guard.next().await {
                    if tx_clone.send(msg).await.is_err() {
                        break;
                    }
                }
            });
        });
        
        Box::new(rx)
    }
    
    fn outgoing_channel(&self) -> mpsc::Sender<(String, Vec<u8>)> {
        self.tx.clone()
    }
    
    fn connected_peers(&self) -> Vec<String> {
        self.connections.lock().unwrap().keys().cloned().collect()
    }
    
    fn start(&mut self) -> Result<(), Self::ErrorType> {
        Ok(())
    }
    
    fn stop(&mut self) -> Result<(), Self::ErrorType> {
        Ok(())
    }
}

/// Mock key manager implementation for testing
#[derive(Debug)]
pub struct MockKeyManager {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl MockKeyManager {
    pub fn new() -> Self {
        Self {
            public_key: Vec::new(),
            private_key: Vec::new(),
        }
    }
}

impl KeyManager for MockKeyManager {
    fn generate_keypair(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.private_key = vec![1, 2, 3, 4];
        self.public_key = vec![5, 6, 7, 8];
        Ok(())
    }
    
    fn public_key_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.public_key.clone())
    }
    
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut signature = Vec::new();
        signature.extend_from_slice(&self.private_key);
        signature.extend_from_slice(message);
        Ok(signature)
    }
    
    fn verify(&self, _message: &[u8], _signature: &[u8], _public_key: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(true)
    }
    
    fn export_keypair(&self, _password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.public_key);
        result.extend_from_slice(&self.private_key);
        Ok(result)
    }
    
    fn import_keypair(&mut self, data: &[u8], _password: &str) -> Result<(), Box<dyn std::error::Error>> {
        if data.len() < 8 {
            return Err("Invalid keypair data length".into());
        }
        self.public_key = data[0..4].to_vec();
        self.private_key = data[4..8].to_vec();
        Ok(())
    }
}

/// Mock config loader implementation for testing
#[derive(Debug)]
pub struct MockConfigLoader {
    config: HashMap<String, String>,
}

impl MockConfigLoader {
    pub fn new() -> Self {
        Self {
            config: HashMap::new(),
        }
    }
}

impl ConfigLoader for MockConfigLoader {
    fn load(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
    
    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
    
    fn get(&self, key: &str) -> Option<String> {
        self.config.get(key).cloned()
    }
    
    fn set(&mut self, key: &str, value: String) -> Result<(), Box<dyn std::error::Error>> {
        self.config.insert(key.to_string(), value);
        Ok(())
    }
    
    fn has(&self, key: &str) -> bool {
        self.config.contains_key(key)
    }
    
    fn remove(&mut self, key: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.config.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor;
    
    #[test]
    fn test_mock_message_handler() {
        let handler = MockMessageHandler::<InternalMessage>::new();
        let message = InternalMessage::new("test", Some("sender"), vec![1, 2, 3]);
        
        // Test handling incoming message
        handler.handle_incoming("peer1", message.clone()).unwrap();
        assert_eq!(handler.get_received_messages().len(), 1);
        
        // Test processing outgoing message
        let processed = handler.process_outgoing("peer2", message.clone()).unwrap();
        assert_eq!(handler.get_processed_messages().len(), 1);
        assert_eq!(processed.message_type(), "test");
        
        // Test peer connection events
        handler.on_peer_connected("peer3").unwrap();
        handler.on_peer_disconnected("peer3").unwrap();
        assert_eq!(handler.get_connected_peers(), vec!["peer3"]);
        assert_eq!(handler.get_disconnected_peers(), vec!["peer3"]);
    }
    
    #[test]
    fn test_mock_network_layer() {
        let mut network = MockNetworkLayer::<InternalMessage>::new();
        
        // Start the network
        network.start().unwrap();
        
        // Connect to a peer
        network.connect("127.0.0.1:8000").unwrap();
        assert_eq!(network.connected_peers().len(), 1);
        
        // Send a message
        let peer_id = network.connected_peers()[0].clone();
        let message = InternalMessage::new("test", Some("sender"), vec![1, 2, 3]);
        network.send_to(&peer_id, message.clone()).unwrap();
        assert_eq!(network.get_sent_messages().len(), 1);
        
        // Simulate incoming message
        network.simulate_incoming_message(&peer_id, message.clone());
        
        // Stop the network
        network.stop().unwrap();
    }
    
    #[test]
    fn test_mock_key_manager() {
        let mut key_manager = MockKeyManager::new();
        
        // Generate keys
        key_manager.generate_keypair().unwrap();
        
        // Export keys
        let exported = key_manager.export_keypair("password").unwrap();
        assert_eq!(exported.len(), 8);
        
        // Create new manager and import keys
        let mut new_manager = MockKeyManager::new();
        new_manager.import_keypair(&exported, "password").unwrap();
        
        // Verify keys were imported correctly
        let public_key = new_manager.public_key_bytes().unwrap();
        assert_eq!(public_key, vec![5, 6, 7, 8]);
    }
    
    #[test]
    fn test_mock_config_loader() {
        let mut config = MockConfigLoader::new();
        
        // Set and get values
        config.set("key1", "value1".to_string()).unwrap();
        assert_eq!(config.get("key1"), Some("value1".to_string()));
        
        // Check has and remove
        assert!(config.has("key1"));
        config.remove("key1").unwrap();
        assert!(!config.has("key1"));
    }
    
    // Keep existing tests
    #[test]
    fn test_mock_transport_adapter() {
        let mut transport = MockTransportAdapter::new();
        
        // Test connection
        let peer_id = transport.connect("127.0.0.1:8000").unwrap();
        assert_eq!(transport.connected_peers().len(), 1);
        
        // Test sending message
        let data = vec![1, 2, 3, 4];
        transport.send_raw(&peer_id, &data).unwrap();
        assert_eq!(transport.get_sent_messages().len(), 1);
        
        // Test incoming message simulation
        transport.simulate_incoming_message(&peer_id, data.clone());
        
        // Test disconnection
        transport.disconnect(&peer_id).unwrap();
        assert_eq!(transport.connected_peers().len(), 0);
    }
} 
