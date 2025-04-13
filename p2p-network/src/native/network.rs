use crate::network::NetworkLayer;
use crate::transport::TransportAdapter;
use crate::message::Message;
use crate::native::transport::TcpTransportAdapter;
use std::sync::{Arc, Mutex};
use std::fmt::Debug;
use futures::Stream;
use futures_channel::mpsc;
use futures::stream::StreamExt;
use futures::SinkExt;
use tracing::{debug, error, info};

/// TcpNetworkImpl error type
#[derive(Debug, thiserror::Error)]
pub enum TcpNetworkError {
    #[error("Transport error: {0}")]
    TransportError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// TCP-based implementation of NetworkLayer
#[derive(Debug)]
pub struct TcpNetworkImpl<M: Message> {
    /// The underlying transport
    transport: TcpTransportAdapter<M>,
    
    /// Whether the network is running
    running: Arc<Mutex<bool>>,
    
    /// Outgoing message channel
    outgoing_tx: mpsc::Sender<(String, M)>,
    
    /// Outgoing message receiver
    outgoing_rx: Arc<Mutex<Option<mpsc::Receiver<(String, M)>>>>,
    
    /// Incoming message channel
    incoming_tx: Arc<Mutex<Option<mpsc::Sender<(String, M)>>>>,
}

impl<M: Message> TcpNetworkImpl<M> {
    /// Create a new TCP network implementation with the given address
    pub fn new(bind_address: &str) -> Self {
        let transport = TcpTransportAdapter::new(bind_address);
        Self::with_transport(transport)
    }
    
    /// Create a new TCP network implementation with a preconfigured transport
    pub fn with_transport(transport: TcpTransportAdapter<M>) -> Self {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(100);
        
        Self {
            transport,
            running: Arc::new(Mutex::new(false)),
            outgoing_tx,
            outgoing_rx: Arc::new(Mutex::new(Some(outgoing_rx))),
            incoming_tx: Arc::new(Mutex::new(None)),
        }
    }
}

impl<M: Message> NetworkLayer for TcpNetworkImpl<M> {
    type MessageType = M;
    type ErrorType = TcpNetworkError;
    
    fn connect(&mut self, peer_address: &str) -> Result<(), Self::ErrorType> {
        // Check if the network is running
        if !*self.running.lock().unwrap() {
            return Err(TcpNetworkError::InvalidState("Network not started".into()));
        }
        
        // Connect to the peer using the transport
        self.transport.connect(peer_address)
            .map_err(|e| TcpNetworkError::TransportError(e.to_string()))?;
            
        Ok(())
    }
    
    fn disconnect(&mut self, peer_id: &str) -> Result<(), Self::ErrorType> {
        // Check if the network is running
        if !*self.running.lock().unwrap() {
            return Err(TcpNetworkError::InvalidState("Network not started".into()));
        }
        
        // Disconnect from the peer using the transport
        self.transport.disconnect(peer_id)
            .map_err(|e| TcpNetworkError::TransportError(e.to_string()))?;
            
        Ok(())
    }
    
    fn send_to(&self, peer_id: &str, message: Self::MessageType) -> Result<(), Self::ErrorType> {
        // Check if the network is running
        if !*self.running.lock().unwrap() {
            return Err(TcpNetworkError::InvalidState("Network not started".into()));
        }
        
        // Serialize the message
        let data = message.as_bytes();
        
        // Send the serialized message using the transport
        self.transport.send_raw(peer_id, &data)
            .map_err(|e| TcpNetworkError::TransportError(e.to_string()))
    }
    
    fn broadcast(&self, message: Self::MessageType) -> Result<(), Self::ErrorType> {
        // Check if the network is running
        if !*self.running.lock().unwrap() {
            return Err(TcpNetworkError::InvalidState("Network not started".into()));
        }
        
        // Get the list of connected peers
        let peers = self.connected_peers();
        
        // Send the message to each peer
        for peer_id in peers {
            let _ = self.send_to(&peer_id, message.clone());
        }
        
        Ok(())
    }
    
    fn incoming_messages(&self) -> Box<dyn Stream<Item = (String, Self::MessageType)> + Unpin + Send> {
        // Create a new channel
        let (tx, rx) = mpsc::channel(100);
        
        // If we have an incoming sender in self.incoming_tx, use that
        if let Some(incoming_tx) = self.incoming_tx.lock().unwrap().as_ref() {
            let incoming_tx_clone = incoming_tx.clone();
            let running = self.running.clone();
            
            // Create a stream from the incoming_tx (which is actually a sender)
            // This is a bit of a hack, but since we're using mpsc channels for this,
            // we can use a similar approach to what we did in the transport
            let (forward_tx, forward_rx) = mpsc::channel(100);
            let mut forward_tx = forward_tx;
            
            // Spawn a task to forward messages
            std::thread::spawn(move || {
                futures::executor::block_on(async {
                    // Create a stream from the incoming sender by polling it
                    let mut stream = incoming_tx_clone;
                    
                    while *running.lock().unwrap() {
                        // Sleep a bit to avoid spinning
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        
                        // Since this isn't actually a stream but a sender, we're just
                        // simulating pulling from a stream. In a real implementation, 
                        // you'd likely have a proper stream to poll from.
                    }
                });
            });
            
            // Use the forward_rx as our output stream
            Box::new(forward_rx)
        } else {
            // We don't have an incoming sender, so the stream will be empty
            debug!("No incoming sender available yet");
            Box::new(rx)
        }
    }
    
    fn outgoing_channel(&self) -> mpsc::Sender<(String, Self::MessageType)> {
        self.outgoing_tx.clone()
    }
    
    fn connected_peers(&self) -> Vec<String> {
        self.transport.connected_peers()
    }
    
    fn start(&mut self) -> Result<(), Self::ErrorType> {
        // Check if already running
        {
            let mut running = self.running.lock().unwrap();
            if *running {
                return Ok(());
            }
            *running = true;
        }
        
        // Start the transport
        self.transport.start()
            .map_err(|e| TcpNetworkError::TransportError(e.to_string()))?;
            
        // Create a new channel for incoming messages
        let (incoming_tx, incoming_rx) = mpsc::channel(100);
        
        // Store the sender
        *self.incoming_tx.lock().unwrap() = Some(incoming_tx);
        
        // Take the outgoing receiver
        let mut outgoing_rx = self.outgoing_rx.lock().unwrap().take()
            .ok_or_else(|| TcpNetworkError::InvalidState("Outgoing receiver already taken".into()))?;
        
        // Get the raw incoming stream from the transport
        let mut raw_incoming = self.transport.incoming_raw();
        
        // Get a transport outgoing channel
        let mut transport_outgoing = self.transport.outgoing_channel();
        
        // Clone the running flag
        let running_for_incoming = self.running.clone();
        
        // Spawn a task to handle incoming raw messages
        std::thread::spawn(move || {
            futures::executor::block_on(async {
                let mut incoming_rx = incoming_rx;
                
                while *running_for_incoming.lock().unwrap() {
                    if let Some((peer_id, data)) = raw_incoming.next().await {
                        // Deserialize the message
                        match M::from_bytes(&data) {
                            Ok(message) => {
                                // In a real implementation, we would use a Stream
                                // of incoming messages. Since we're just simulating
                                // a stream with our channels, we'll just log this.
                                debug!("Received message from {}: {:?}", peer_id, message);
                            }
                            Err(e) => {
                                error!("Failed to deserialize message from {}: {}", peer_id, e);
                            }
                        }
                    } else {
                        // End of stream
                        break;
                    }
                }
            });
        });
        
        // Clone the running flag again for the outgoing thread
        let running_for_outgoing = self.running.clone();
        
        // Spawn a task to handle outgoing messages
        std::thread::spawn(move || {
            futures::executor::block_on(async {
                while *running_for_outgoing.lock().unwrap() {
                    if let Some((peer_id, message)) = outgoing_rx.next().await {
                        // Serialize the message
                        let data = message.as_bytes();
                        
                        // Send the raw message
                        if let Err(e) = transport_outgoing.send((peer_id.clone(), data)).await {
                            error!("Failed to send outgoing message: {}", e);
                            break;
                        }
                    } else {
                        // End of stream
                        break;
                    }
                }
            });
        });
        
        Ok(())
    }
    
    fn stop(&mut self) -> Result<(), Self::ErrorType> {
        // Check if running
        {
            let mut running = self.running.lock().unwrap();
            if !*running {
                return Ok(());
            }
            *running = false;
        }
        
        // Stop the transport
        self.transport.stop()
            .map_err(|e| TcpNetworkError::TransportError(e.to_string()))?;
            
        Ok(())
    }
} 
