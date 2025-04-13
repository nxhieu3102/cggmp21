use crate::message::Message;
use std::error::Error;
use std::fmt::Debug;
use futures::Stream;
use futures_channel::mpsc;

/// TransportAdapter trait defines the interface for implementing different network transport mechanisms.
/// 
/// This abstraction allows the library to support different transport protocols (TCP, WebSockets, etc.)
/// while maintaining a consistent interface. Implementations should handle the specifics of 
/// the underlying transport protocol.
pub trait TransportAdapter: Send + Sync + Debug {
    /// Type of message that this transport adapter handles
    type MessageType: Message;
    
    /// Type of error that this transport adapter can produce
    type ErrorType: Error + Send + Sync + 'static;
    
    /// Initialize the transport adapter with any required configuration
    fn initialize(&mut self) -> Result<(), Self::ErrorType>;
    
    /// Open a connection to a peer
    /// 
    /// # Arguments
    /// * `address` - The address or connection string for the peer
    /// 
    /// # Returns
    /// * `Ok(String)` - The peer ID of the successfully connected peer
    /// * `Err(Self::ErrorType)` - If the connection failed
    fn connect(&mut self, address: &str) -> Result<String, Self::ErrorType>;
    
    /// Close a connection to a peer
    /// 
    /// # Arguments
    /// * `peer_id` - The identifier of the peer to disconnect from
    /// 
    /// # Returns
    /// * `Ok(())` if the disconnection was successful
    /// * `Err(Self::ErrorType)` if an error occurred during disconnection
    fn disconnect(&mut self, peer_id: &str) -> Result<(), Self::ErrorType>;
    
    /// Send raw message data to a peer
    /// 
    /// # Arguments
    /// * `peer_id` - The identifier of the peer to send the message to
    /// * `data` - The serialized message data to send
    /// 
    /// # Returns
    /// * `Ok(())` if the message was sent successfully
    /// * `Err(Self::ErrorType)` if an error occurred during sending
    fn send_raw(&self, peer_id: &str, data: &[u8]) -> Result<(), Self::ErrorType>;
    
    /// Get a stream of incoming raw message data
    /// 
    /// # Returns
    /// * A Stream yielding tuples of (peer_id, data) where data is the raw message bytes
    fn incoming_raw(&self) -> Box<dyn Stream<Item = (String, Vec<u8>)> + Unpin + Send>;
    
    /// Get a channel for sending outgoing raw message data
    /// 
    /// # Returns
    /// * A Sender channel for outgoing raw messages
    fn outgoing_channel(&self) -> mpsc::Sender<(String, Vec<u8>)>;
    
    /// Get the list of currently connected peers
    /// 
    /// # Returns
    /// * A vector of peer identifiers
    fn connected_peers(&self) -> Vec<String>;
    
    /// Start the transport service
    /// 
    /// # Returns
    /// * `Ok(())` if the service started successfully
    /// * `Err(Self::ErrorType)` if an error occurred during startup
    fn start(&mut self) -> Result<(), Self::ErrorType>;
    
    /// Stop the transport service
    /// 
    /// # Returns
    /// * `Ok(())` if the service stopped successfully
    /// * `Err(Self::ErrorType)` if an error occurred during shutdown
    fn stop(&mut self) -> Result<(), Self::ErrorType>;
} 
