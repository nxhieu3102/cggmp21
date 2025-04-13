use crate::message::Message;
use std::fmt::Debug;
use futures::Stream;
use futures_channel::mpsc;
use std::error::Error;

/// Abstract interface for network communications
pub trait NetworkLayer: Send + Sync + Debug {
    /// Type of message that the network layer handles
    type MessageType: Message;
    
    /// Type of error that the network layer can produce
    type ErrorType: Error + Send + Sync + 'static;
    
    /// Connect to a peer
    fn connect(&mut self, peer_address: &str) -> Result<(), Self::ErrorType>;
    
    /// Disconnect from a peer
    fn disconnect(&mut self, peer_id: &str) -> Result<(), Self::ErrorType>;
    
    /// Send a message to a specific peer
    fn send_to(&self, peer_id: &str, message: Self::MessageType) -> Result<(), Self::ErrorType>;
    
    /// Broadcast a message to all connected peers
    fn broadcast(&self, message: Self::MessageType) -> Result<(), Self::ErrorType>;
    
    /// Get a stream of incoming messages
    fn incoming_messages(&self) -> Box<dyn Stream<Item = (String, Self::MessageType)> + Unpin + Send>;
    
    /// Get a channel for sending outgoing messages
    fn outgoing_channel(&self) -> mpsc::Sender<(String, Self::MessageType)>;
    
    /// Get the list of connected peers
    fn connected_peers(&self) -> Vec<String>;
    
    /// Start the network service
    fn start(&mut self) -> Result<(), Self::ErrorType>;
    
    /// Stop the network service
    fn stop(&mut self) -> Result<(), Self::ErrorType>;
} 
