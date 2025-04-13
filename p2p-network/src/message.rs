use serde::{Serialize, Deserialize};
use std::fmt::Debug;

/// Core message trait that must be implemented by all message types
pub trait Message: Clone + Send + Sync + Debug + Serialize + for<'de> Deserialize<'de> + 'static {
    /// Get the message type identifier
    fn message_type(&self) -> &str;
    
    /// Get the sender ID if available
    fn sender_id(&self) -> Option<&str>;
    
    /// Get the message payload as bytes
    fn as_bytes(&self) -> Vec<u8>;
    
    /// Create a message from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>>;
}

/// Internal message container that is platform-agnostic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalMessage {
    /// Message type identifier
    pub message_type: String,
    
    /// Sender identifier
    pub sender_id: Option<String>,
    
    /// Message payload
    pub payload: Vec<u8>,
    
    /// Timestamp when the message was created
    pub timestamp: u64,
}

impl InternalMessage {
    /// Create a new internal message
    pub fn new(message_type: &str, sender_id: Option<&str>, payload: Vec<u8>) -> Self {
        Self {
            message_type: message_type.to_string(),
            sender_id: sender_id.map(|s| s.to_string()),
            payload,
            timestamp: get_timestamp(),
        }
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

impl Message for InternalMessage {
    fn message_type(&self) -> &str {
        &self.message_type
    }
    
    fn sender_id(&self) -> Option<&str> {
        self.sender_id.as_deref()
    }
    
    fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
    
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let message = bincode::deserialize(bytes)?;
        Ok(message)
    }
}

/// Message with cryptographic verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    /// The wrapped message
    pub message: InternalMessage,
    
    /// The signature of the message
    pub signature: Vec<u8>,
    
    /// The public key of the signer
    pub public_key: Vec<u8>,
} 
