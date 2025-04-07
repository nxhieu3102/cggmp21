use anyhow::{Context as AnyhowContext, Result};
use futures::SinkExt;
use futures_channel::mpsc;
use round_based::{Incoming, MessageDestination, Outgoing};
use serde::{Serialize, Deserialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{RwLock, mpsc as tokio_mpsc},
};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use hex;
use rand::Rng;
use tracing::{debug, error, info, trace, warn};

// Define our internal message type for key exchange
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum InternalMessage<M> {
    ProtocolMessage(M),
    KeyExchange { node_id: u16, public_key_hex: String },
}

// Define our own message type enum that can be serialized/deserialized
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum MessageType {
    Broadcast,
    P2P,
}

impl MessageType {
    // Convert to round_based::MessageType
    fn to_round_based(&self) -> round_based::MessageType {
        match self {
            MessageType::Broadcast => round_based::MessageType::Broadcast,
            MessageType::P2P => round_based::MessageType::P2P,
        }
    }
    
    // Convert from round_based::MessageType
    fn from_round_based(msg_type: round_based::MessageType) -> Self {
        match msg_type {
            round_based::MessageType::Broadcast => MessageType::Broadcast,
            round_based::MessageType::P2P => MessageType::P2P,
            _ => MessageType::Broadcast, // Default for unknown types
        }
    }
}

// Define a structure to hold the signed message
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedMessage<M> {
    pub sender_id: u16,
    pub message: InternalMessage<M>,
    pub signature: Vec<u8>,
    pub msg_type: MessageType,
}

// Key management struct to hold all peers' public keys and our keypair
#[derive(Clone)]
pub struct KeyManager {
    pub node_id: u16,
    // Store key bytes rather than Keypair which isn't Clone
    pub secret_key_bytes: Option<Vec<u8>>,
    pub public_key_bytes: Option<Vec<u8>>, 
    pub public_keys: HashMap<u16, PublicKey>,
}

impl KeyManager {
    pub fn new(node_id: u16) -> Self {
        KeyManager {
            node_id,
            secret_key_bytes: None,
            public_key_bytes: None,
            public_keys: HashMap::new(),
        }
    }

    pub fn load_keypair_from_hex(&mut self, private_key_hex: &str) -> Result<(), anyhow::Error> {
        let secret_bytes = hex::decode(private_key_hex)?;
        let secret = SecretKey::from_bytes(&secret_bytes)?;
        let public = PublicKey::from(&secret);
        
        // Store the bytes instead of the keypair
        self.secret_key_bytes = Some(secret_bytes);
        self.public_key_bytes = Some(public.to_bytes().to_vec());
        
        // Add our own public key
        self.public_keys.insert(self.node_id, public);
        Ok(())
    }

    pub fn add_public_key(&mut self, peer_id: u16, public_key_hex: &str) -> Result<(), anyhow::Error> {
        let public_bytes = hex::decode(public_key_hex)?;
        let public = PublicKey::from_bytes(&public_bytes)?;
        self.public_keys.insert(peer_id, public);
        info!("Added public key for peer ID: {}", peer_id);
        Ok(())
    }

    pub fn get_public_key_hex(&self) -> Option<String> {
        self.public_key_bytes.as_ref().map(|bytes| hex::encode(bytes))
    }

    pub fn sign_message<M: Serialize>(&self, message: &M) -> Result<Vec<u8>, anyhow::Error> {
        if let Some(ref secret_bytes) = self.secret_key_bytes {
            let secret = SecretKey::from_bytes(secret_bytes)?;
            let public = match &self.public_key_bytes {
                Some(bytes) => PublicKey::from_bytes(bytes)?,
                None => PublicKey::from(&secret),
            };
            
            let keypair = Keypair { secret, public };
            let message_bytes = bincode::serialize(message)?;
            Ok(keypair.sign(&message_bytes).to_bytes().to_vec())
        } else {
            Err(anyhow::anyhow!("No keypair available for signing"))
        }
    }

    pub fn verify_signature<M: Serialize>(&self, sender_id: u16, message: &M, signature: &[u8]) -> Result<bool, anyhow::Error> {
        // Print all available public keys with their sender IDs
        if let Some(public_key) = self.public_keys.get(&sender_id) {
            let message_bytes = bincode::serialize(message)?;
            let signature = Signature::from_bytes(signature)?;
            Ok(public_key.verify(&message_bytes, &signature).is_ok())
        } else {
            Err(anyhow::anyhow!("Public key not found for sender ID: {}", sender_id))
        }
    }
}

/// Creates a communication channel for a TCP stream
fn create_stream_channel<M>(
    stream: TcpStream,
) -> (
    tokio::io::ReadHalf<TcpStream>,
    tokio_mpsc::Sender<SignedMessage<M>>,
)
where
    M: Send + 'static + Serialize,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = tokio_mpsc::channel(32);

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let encoded_msg = bincode::serialize(&msg).expect("Failed to serialize message");
            if writer.write_all(&encoded_msg).await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
    });

    (reader, tx)
}

// Send our public key to a peer
async fn send_key_exchange<M>(
    sender: &tokio_mpsc::Sender<SignedMessage<M>>,
    key_manager: &Arc<RwLock<KeyManager>>,
) -> Result<()>
where
    M: Send + Sync + 'static + Serialize,
{
    let key_manager_read = key_manager.read().await;
    
    // Get our node ID and public key
    let node_id = key_manager_read.node_id;
    let public_key_hex = match key_manager_read.get_public_key_hex() {
        Some(pk) => pk,
        None => return Err(anyhow::anyhow!("No public key available for exchange")),
    };
    
    // Create the key exchange message
    let key_exchange = InternalMessage::KeyExchange {
        node_id,
        public_key_hex,
    };
    
    // Sign the message
    let signature = key_manager_read.sign_message(&key_exchange)?;
    
    // Create the signed message
    let signed_message = SignedMessage {
        sender_id: node_id,
        message: key_exchange,
        signature,
        msg_type: MessageType::Broadcast,
    };
    
    // Send the signed message
    sender.send(signed_message).await
        .map_err(|_| anyhow::anyhow!("Failed to send key exchange message"))?;
    
    debug!("Sent public key to peer");
    Ok(())
}

/// Handle messages received from a TCP stream
async fn handle_messages<M>(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    address: SocketAddr,
    peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
    incoming_tx: mpsc::Sender<Incoming<M>>,
    key_manager: Arc<RwLock<KeyManager>>,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<SignedMessage<M>>>>>,
) 
where
    M: Send + Sync + 'static + for<'de> serde::de::Deserialize<'de> + Serialize + Clone,
{
    let mut buffer = [0u8; 1024];
    let mut incoming_tx = incoming_tx;

    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                // trace!("Received {} bytes from {}", n, address);
                
                // Try to deserialize as a SignedMessage with our InternalMessage
                if let Ok(signed_msg) = bincode::deserialize::<SignedMessage<M>>(&buffer[..n]) {
                    // debug!("Received signed message from {:?}, claimed sender: {}, msg_type: {:?}", 
                    //          address, signed_msg.sender_id, signed_msg.msg_type);
                    
                    // First handle key exchange messages
                    if let InternalMessage::KeyExchange { node_id, public_key_hex } = &signed_msg.message {
                        // info!("Received key exchange from node: {}", node_id);
                        
                        // Check if we already have this peer's key
                        let already_have_key = {
                            let key_manager_read = key_manager.read().await;
                            key_manager_read.public_keys.contains_key(node_id)
                        };
                        
                        if !already_have_key {
                            // Add the peer's public key to our key manager
                            {
                                let mut key_manager_write = key_manager.write().await;
                                if let Err(e) = key_manager_write.add_public_key(*node_id, public_key_hex) {
                                    error!("Error adding public key: {}", e);
                                    continue;
                                }
                            }
                            
                            // Update peers_id mapping
                            {
                                let mut peers_id_write = peers_id.write().await;
                                peers_id_write.insert(*node_id, address);
                            }
                            
                            // Get our key manager to send our key back
                            let peers_read = peers.read().await;
                            if let Some(tx) = peers_read.get(&address) {
                                if let Err(e) = send_key_exchange(tx, &key_manager).await {
                                    error!("Failed to send key exchange back: {}", e);
                                }
                            }
                        } else {
                            debug!("Already have public key for node {}, not responding", node_id);
                        }
                        
                        continue; // Don't forward key exchange messages to the application
                    }
                    
                    // For protocol messages, verify the signature
                    let key_manager_read = key_manager.read().await;
                    match key_manager_read.verify_signature(signed_msg.sender_id, &signed_msg.message, &signed_msg.signature) {
                        Ok(true) => {
                            // Process the actual protocol message
                            if let InternalMessage::ProtocolMessage(actual_msg) = signed_msg.message {
                                trace!("Forwarding protocol message from sender: {}, type: {:?}", 
                                       signed_msg.sender_id, signed_msg.msg_type);
                                
                                // Create incoming message with verified sender_id
                                let incoming_msg = Incoming {
                                    id: rand::thread_rng().gen::<u64>(),
                                    sender: signed_msg.sender_id,
                                    msg_type: signed_msg.msg_type.to_round_based(),
                                    msg: actual_msg,
                                };
                                
                                if incoming_tx.send(incoming_msg).await.is_err() {
                                    error!("Failed to forward message to MPC protocol");
                                    break;
                                } else {
                                    debug!("Successfully forwarded message to MPC protocol");
                                }
                            }
                        },
                        Ok(false) => {
                            warn!("Invalid signature from claimed sender: {}", signed_msg.sender_id);
                        },
                        Err(e) => {
                            error!("Error verifying signature: {}", e);
                        }
                    }
                } else {
                    debug!("Failed to deserialize as SignedMessage, trying legacy format");
                    // Fallback for legacy messages or incompatible format
                    if let Ok(msg) = bincode::deserialize::<M>(&buffer[..n]) {
                        debug!("Received unsigned message from {:?}", address);
                        
                        // Try to find the peer ID
                        let peer_id = find_peer_id(&peers_id, address).await;
                        
                        let incoming_msg = Incoming {
                            id: rand::thread_rng().gen::<u64>(),
                            sender: peer_id,
                            msg_type: round_based::MessageType::Broadcast,
                            msg,
                        };
                        if incoming_tx.send(incoming_msg).await.is_err() {
                            error!("Failed to forward legacy message to MPC protocol");
                            break;
                        } else {
                            debug!("Successfully forwarded legacy message to MPC protocol");
                        }
                    } else {
                        error!("Could not deserialize message in any format");
                    }
                }
            }
            Err(e) => {
                error!("Error reading from socket: {}", e);
                break;
            }
        }
    }
}

/// Find peer ID corresponding to an address
async fn find_peer_id(peers_id: &Arc<RwLock<HashMap<u16, SocketAddr>>>, address: SocketAddr) -> u16 {
    peers_id
        .read()
        .await
        .iter()
        .find(|(_, addr)| **addr == address)
        .map(|(id, _)| *id)
        .unwrap_or(0)
}

pub async fn connect<M>(
    address: SocketAddr,
    incoming_tx: mpsc::Sender<Incoming<M>>,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<SignedMessage<M>>>>>,
    peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
    key_manager: Arc<RwLock<KeyManager>>,
) -> Result<()>
where
    M: Send + Sync + 'static + for<'de> serde::de::Deserialize<'de> + Serialize + Clone,
{
    let stream = TcpStream::connect(address)
        .await
        .with_context(|| format!("Failed to connect to {}", address))?;
    
    let (reader, tx) = create_stream_channel(stream);
    peers.write().await.insert(address, tx.clone());

    // Send our public key to the new peer
    send_key_exchange(&tx, &key_manager).await?;

    // Clone Arc before moving it into the task
    let peers_id_clone = peers_id.clone();
    let key_manager_clone = key_manager.clone();
    let peers_clone = peers.clone();
    tokio::spawn(async move {
        handle_messages(reader, address, peers_id_clone, incoming_tx, key_manager_clone, peers_clone).await;
    });

    Ok(())
}

pub async fn handle_connection<'a, M>(
    stream: TcpStream,
    address: SocketAddr,
    incoming_tx: mpsc::Sender<Incoming<M>>,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<SignedMessage<M>>>>>,
    peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
    key_manager: Arc<RwLock<KeyManager>>,
) where
    M: Send + Sync + 'static + for<'de> serde::de::Deserialize<'de> + Serialize + Clone,
{
    let (reader, tx) = create_stream_channel(stream);
    peers.write().await.insert(address, tx.clone());
    
    // Send our public key to the new peer
    if let Err(e) = send_key_exchange(&tx, &key_manager).await {
        error!("Failed to send key exchange: {}", e);
    }

    // Clone Arc before moving it into task
    let peers_id_clone = peers_id.clone();
    let key_manager_clone = key_manager.clone();
    let peers_clone = peers.clone();
    handle_messages(reader, address, peers_id_clone, incoming_tx, key_manager_clone, peers_clone).await;
    
    peers.write().await.remove(&address);
}

pub async fn handle_outgoing<M>(
    outgoing: Outgoing<M>,
    peers: &Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<SignedMessage<M>>>>>,
    peers_id: &Arc<RwLock<HashMap<u16, SocketAddr>>>,
    key_manager: &Arc<RwLock<KeyManager>>,
) -> Result<()>
where
    M: Send + Sync + Clone + 'static + Serialize,
{

    // Create a signed message
    let key_manager_read = key_manager.read().await;
    let node_id = key_manager_read.node_id;
    
    // Wrap the protocol message
    let internal_msg = InternalMessage::ProtocolMessage(outgoing.msg);
    debug!("Sending message to: {:?}", outgoing.recipient);
    
    // Sign the message
    let signature = match key_manager_read.sign_message(&internal_msg) {
        Ok(sig) => sig,
        Err(e) => {
            error!("Failed to sign message: {}", e);
            return Err(anyhow::anyhow!("Failed to sign message"));
        }
    };
    
    // Determine the message type based on the recipient
    let msg_type = match outgoing.recipient {
        MessageDestination::AllParties => MessageType::Broadcast,
        MessageDestination::OneParty(_) => MessageType::P2P,
    };
    
    let signed_message = SignedMessage {
        sender_id: node_id,
        message: internal_msg,
        signature,
        msg_type,
    };

    let receivers = match outgoing.recipient {
        MessageDestination::AllParties => peers.read().await.values().cloned().collect::<Vec<_>>(),
        MessageDestination::OneParty(peer_id) => {
            let peers_id_read = peers_id.read().await;
            let peers_read = peers.read().await;
            
            peers_id_read
                .get(&peer_id)
                .and_then(|addr| peers_read.get(addr))
                .map(|sender| vec![sender.clone()])
                .unwrap_or_default()
        }
    };

    for receiver in receivers {
        trace!("Sending message with sender_id: {} and msg_type: {:?}", signed_message.sender_id, signed_message.msg_type);
        if let Err(e) = receiver.send(signed_message.clone()).await {
            error!("Failed to send message: {}", e);
        }
    }

    Ok(())
}
