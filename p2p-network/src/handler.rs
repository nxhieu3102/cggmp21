use crate::message::Message;
use std::error::Error;
use std::fmt::Debug;

/// MessageHandler trait defines the interface for processing incoming and outgoing messages.
/// 
/// Implementations of this trait are responsible for handling the application-specific
/// logic when messages are received or before they are sent. This enables separation of
/// network transport from message processing logic.
pub trait MessageHandler: Send + Sync + Debug {
    /// The type of message this handler processes
    type MessageType: Message;
    
    /// The type of error that can occur during message handling
    type ErrorType: Error + Send + Sync + 'static;
    
    /// Handle an incoming message from a peer
    /// 
    /// # Arguments
    /// * `peer_id` - The identifier of the peer that sent the message
    /// * `message` - The message that was received
    /// 
    /// # Returns
    /// * `Ok(())` if the message was handled successfully
    /// * `Err(Self::ErrorType)` if an error occurred during handling
    fn handle_incoming(&self, peer_id: &str, message: Self::MessageType) -> Result<(), Self::ErrorType>;
    
    /// Process an outgoing message before it is sent
    /// 
    /// This method allows for transforming, logging, or adding metadata to messages
    /// before they are sent over the network.
    /// 
    /// # Arguments
    /// * `peer_id` - The identifier of the peer to which the message will be sent
    /// * `message` - The message to be sent
    /// 
    /// # Returns
    /// * `Ok(Self::MessageType)` - The processed message to be sent
    /// * `Err(Self::ErrorType)` - If an error occurred during processing
    fn process_outgoing(&self, peer_id: &str, message: Self::MessageType) -> Result<Self::MessageType, Self::ErrorType>;
    
    /// Called when a new peer connection is established
    /// 
    /// # Arguments
    /// * `peer_id` - The identifier of the newly connected peer
    /// 
    /// # Returns
    /// * `Ok(())` if the connection was handled successfully
    /// * `Err(Self::ErrorType)` if an error occurred during handling
    fn on_peer_connected(&self, peer_id: &str) -> Result<(), Self::ErrorType>;
    
    /// Called when a peer connection is lost or closed
    /// 
    /// # Arguments
    /// * `peer_id` - The identifier of the disconnected peer
    /// 
    /// # Returns
    /// * `Ok(())` if the disconnection was handled successfully
    /// * `Err(Self::ErrorType)` if an error occurred during handling
    fn on_peer_disconnected(&self, peer_id: &str) -> Result<(), Self::ErrorType>;
} 
