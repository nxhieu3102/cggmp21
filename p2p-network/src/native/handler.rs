use crate::handler::MessageHandler;
use crate::message::Message;
use std::fmt::Debug;
use std::marker::PhantomData;
use tracing::{debug, info, warn};

/// Basic message handler error
#[derive(Debug, thiserror::Error)]
pub enum BasicHandlerError {
    #[error("Message processing error: {0}")]
    ProcessingError(String),
}

/// Basic implementation of MessageHandler that logs messages but doesn't modify them
#[derive(Debug, Clone)]
pub struct BasicMessageHandler<M: Message> {
    _marker: PhantomData<M>,
}

impl<M: Message> BasicMessageHandler<M> {
    /// Create a new basic message handler
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<M: Message> Default for BasicMessageHandler<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: Message> MessageHandler for BasicMessageHandler<M> {
    type MessageType = M;
    type ErrorType = BasicHandlerError;
    
    fn handle_incoming(&self, peer_id: &str, message: Self::MessageType) -> Result<(), Self::ErrorType> {
        info!("Received message from {}: type={}", peer_id, message.message_type());
        debug!("Message details: {:?}", message);
        Ok(())
    }
    
    fn process_outgoing(&self, peer_id: &str, message: Self::MessageType) -> Result<Self::MessageType, Self::ErrorType> {
        info!("Sending message to {}: type={}", peer_id, message.message_type());
        debug!("Message details: {:?}", message);
        Ok(message)
    }
    
    fn on_peer_connected(&self, peer_id: &str) -> Result<(), Self::ErrorType> {
        info!("Peer connected: {}", peer_id);
        Ok(())
    }
    
    fn on_peer_disconnected(&self, peer_id: &str) -> Result<(), Self::ErrorType> {
        info!("Peer disconnected: {}", peer_id);
        Ok(())
    }
} 
