// Example of a P2P DKG using cggmp21
// Run: cargo run --bin p2p_example <config file>
// Node 1: cargo run --bin p2p_example test-data/p2p_example/dkg/node1.yaml
// Node 2: cargo run --bin p2p_example test-data/p2p_example/dkg/node2.yaml
// Node 3: cargo run --bin p2p_example test-data/p2p_example/dkg/node3.yaml

mod config;
mod handlers;
mod node;

use anyhow::{Context, Result};
use cggmp21::keygen::msg::threshold::Msg;
use config::load_config;
use futures::{SinkExt, StreamExt, Stream, Sink};
use node::Node;
use rand::rngs::OsRng;
use round_based::{Incoming, Outgoing, ProtocolMessage};
use std::time::Duration;
use std::error::Error as StdError;
use std::fmt;
use std::pin::Pin;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber;
use serde::{Deserialize, Serialize};

// Define types for Box<dyn Stream> and Box<dyn Sink>
type BoxStream<'a, T> = Pin<Box<dyn Stream<Item = T> + Send + 'a>>;
type BoxSink<'a, T, E> = Pin<Box<dyn Sink<T, Error = E> + Send + 'a>>;

// Define types for the cryptographic primitives
type E = generic_ec::curves::Secp256k1;
type D = sha2::Sha256;
type L = cggmp21::security_level::SecurityLevel128;

// Create a unified message type that can handle all protocol steps
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum UnifiedMsg<E: generic_ec::Curve, L: cggmp21::security_level::SecurityLevel, D: sha2::digest::Digest> {
    // DKG Messages
    DKG(cggmp21::keygen::msg::threshold::Msg<E, L, D>),
    // AuxInfo Messages
    AuxInfo(cggmp21::key_refresh::msg::aux_only::Msg<D, L>),
    // Signing Messages
    Signing(cggmp21::signing::msg::Msg<E, D>),
}

// Manual Debug implementation since inner types don't implement Debug
impl<E: generic_ec::Curve, L: cggmp21::security_level::SecurityLevel, D: sha2::digest::Digest> std::fmt::Debug for UnifiedMsg<E, L, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DKG(_) => write!(f, "UnifiedMsg::DKG(...)"),
            Self::AuxInfo(_) => write!(f, "UnifiedMsg::AuxInfo(...)"),
            Self::Signing(_) => write!(f, "UnifiedMsg::Signing(...)"),
        }
    }
}

// Implement ProtocolMessage for UnifiedMsg
impl<E: generic_ec::Curve, L: cggmp21::security_level::SecurityLevel, D: sha2::digest::Digest> ProtocolMessage for UnifiedMsg<E, L, D> {
    fn round(&self) -> u16 {
        match self {
            Self::DKG(msg) => msg.round(),
            Self::AuxInfo(msg) => msg.round(),
            Self::Signing(msg) => msg.round(),
        }
    }
}

// Custom error type that implements StdError
#[derive(Debug, Clone)]
struct CustomError(String);

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl StdError for CustomError {}

/// Wait for the specified duration asynchronously with informative messages
async fn sleep_with_message(duration: Duration, message: &str) {
    println!("{}", message);
    tokio::time::sleep(duration).await;
    println!("Waking up...");
}

/// Display the node's connection information for debugging
async fn display_node_info<M>(node: &Node<M>) {
    println!("=========================");
    println!("Node address: {}", node.address);
    
    println!("Peer id mapping:");
    for (id, addr) in node.peers_id.read().await.iter() {
        println!("  Peer id: {} -> address: {}", id, addr);
    }

    println!("Connected peers:");
    for (addr, _) in node.peers.read().await.iter() {
        println!("  Peer address: {}", addr);
    }
    println!("=========================");
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber for logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();
        
    // Log setup information
    info!("Starting P2P example application");
    
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        error!("Missing config file argument");
        eprintln!("Usage: cargo run --bin p2p_example <config file>");
        return Ok(());
    }

    // Load the node configuration
    debug!("Loading configuration from {}", &args[1]);
    let config = load_config(&args[1])
        .context(format!("Failed to load config from {}", &args[1]))?;
    
    // Extract the node id before config is moved
    let i = config.node.id;
    trace!("Node ID: {}", i);

    // Set up the P2P network with UnifiedMsg instead of specific message types
    info!("Initializing P2P network node...");
    let (node, incoming, outgoing) =
        Node::<UnifiedMsg<E, L, D>>::new(config.clone()).await?;

    // Warning about large messages
    info!("This example handles large messages (>200KB) through length-prefixed framing");
    info!("If you still encounter message size issues, check network connections and buffer sizes");

    // Wait for all nodes to start and connect
    debug!("Waiting for other nodes to start up");
    sleep_with_message(
        Duration::from_secs(10),
        "Sleeping for 10 seconds to allow all nodes to start...",
    ).await;

    // Wait to receive messages from other peers
    sleep_with_message(
        Duration::from_secs(3),
        "Sleeping for 3 seconds to receive messages...",
    ).await;

    // Create a broadcast channel for distributing incoming messages
    let (incoming_tx, _) = broadcast::channel::<Result<Incoming<UnifiedMsg<E, L, D>>, CustomError>>(100);

    // Create mpsc channel for collecting outgoing messages
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Outgoing<UnifiedMsg<E, L, D>>>(100);

    // Forward incoming messages to the broadcast channel
    let incoming_tx_clone = incoming_tx.clone();
    tokio::spawn(async move {
        let mut incoming = incoming.map(|msg| {
            // Debug: Print sender ID information for each incoming message
            match &msg {
                Ok(incoming_msg) => {
                    println!("[DEBUG INCOMING] Message from sender: {}, type: {:?}, id: {}", 
                        incoming_msg.sender, incoming_msg.msg_type, incoming_msg.id);
                }
                Err(e) => {
                    println!("[DEBUG INCOMING] Error message: {}", e);
                }
            }
            msg.map_err(|e| CustomError(e.to_string()))
        });
        
        while let Some(msg) = incoming.next().await {
            if incoming_tx_clone.send(msg).is_err() {
                break;
            }
        }
    });

    // Forward outgoing messages to the outgoing sink
    tokio::spawn(async move {
        let mut outgoing = outgoing;
        while let Some(msg) = outgoing_rx.recv().await {
            if outgoing.send(msg).await.is_err() {
                break;
            }
        }
    });

    let eid = cggmp21::ExecutionId::new(b"execution id, unique per protocol execution");
    let n = 3;
    let t = 2;
    let pregenerated_primes = cggmp21::PregeneratedPrimes::generate(&mut OsRng);

    // Need to create adapter types to convert between unified messages and protocol-specific messages
    let aux_gen_party = {
        // Create an adapter that filters for AuxInfo messages
        let aux_incoming = {
            let rx = incoming_tx.subscribe();
            let stream = futures::stream::unfold(rx, |mut rx| async move {
                match rx.recv().await {
                    Ok(msg) => {
                        let filtered_msg = match msg {
                            Ok(incoming_msg) => {
                                if let UnifiedMsg::AuxInfo(aux_msg) = incoming_msg.msg {
                                    Some(Ok(round_based::Incoming {
                                        sender: incoming_msg.sender,
                                        id: incoming_msg.id,
                                        msg_type: incoming_msg.msg_type,
                                        msg: aux_msg,
                                    }))
                                } else {
                                    None
                                }
                            },
                            Err(e) => Some(Err(e)),
                        };
                        Some((filtered_msg, rx))
                    },
                    Err(_) => Some((None, rx)), // Broadcast error
                }
            }).filter_map(|x| async move { x });
            Box::pin(stream) as BoxStream<'static, Result<Incoming<_>, CustomError>>
        };
        
        // Create an adapter for outgoing AuxInfo messages
        let aux_outgoing = {
            let outgoing_tx = outgoing_tx.clone();
            
            let sink = futures::sink::unfold((), move |_, msg: Outgoing<cggmp21::key_refresh::msg::aux_only::Msg<D, L>>| {
                let outgoing_tx = outgoing_tx.clone();
                async move {
                    let unified_msg = Outgoing {
                        recipient: msg.recipient,
                        msg: UnifiedMsg::AuxInfo(msg.msg),
                    };
                    let cloned_msg = unified_msg.clone();
                    
                    outgoing_tx.send(unified_msg).await
                        .map_err(|_| mpsc::error::SendError(cloned_msg))
                        .map(|_| ())
                }
            });
            
            Box::pin(sink) as BoxSink<'static, Outgoing<cggmp21::key_refresh::msg::aux_only::Msg<D, L>>, mpsc::error::SendError<_>>
        };
        
        round_based::MpcParty::connected((aux_incoming, aux_outgoing))
    };

    let aux_info = cggmp21::key_refresh::AuxInfoGenerationBuilder::new_aux_gen(
        eid, 
        i as u16, 
        n, 
        pregenerated_primes
    ).start(&mut OsRng, aux_gen_party)
    .await?;

    info!("Aux info generated");

    info!("Starting DKG with id: {}, n: {}, t: {}", i, n, t);

    // DKG party adapter
    let dkg_party = {
        // Create an adapter that filters for DKG messages
        let dkg_incoming = {
            let rx = incoming_tx.subscribe();
            let stream = futures::stream::unfold(rx, |mut rx| async move {
                match rx.recv().await {
                    Ok(msg) => {
                        let filtered_msg = match msg {
                            Ok(incoming_msg) => {
                                if let UnifiedMsg::DKG(dkg_msg) = incoming_msg.msg {
                                    Some(Ok(round_based::Incoming {
                                        sender: incoming_msg.sender,
                                        id: incoming_msg.id,
                                        msg_type: incoming_msg.msg_type,
                                        msg: dkg_msg,
                                    }))
                                } else {
                                    None
                                }
                            },
                            Err(e) => Some(Err(e)),
                        };
                        Some((filtered_msg, rx))
                    },
                    Err(_) => Some((None, rx)), // Broadcast error
                }
            }).filter_map(|x| async move { x });
            Box::pin(stream) as BoxStream<'static, Result<Incoming<_>, CustomError>>
        };
        
        // Create an adapter for outgoing DKG messages
        let dkg_outgoing = {
            let outgoing_tx = outgoing_tx.clone();
            
            let sink = futures::sink::unfold((), move |_, msg: Outgoing<cggmp21::keygen::msg::threshold::Msg<E, L, D>>| {
                let outgoing_tx = outgoing_tx.clone();
                async move {
                    let unified_msg = Outgoing {
                        recipient: msg.recipient,
                        msg: UnifiedMsg::DKG(msg.msg),
                    };
                    let cloned_msg = unified_msg.clone();
                    
                    outgoing_tx.send(unified_msg).await
                        .map_err(|_| mpsc::error::SendError(cloned_msg))
                        .map(|_| ())
                }
            });
            
            Box::pin(sink) as BoxSink<'static, Outgoing<cggmp21::keygen::msg::threshold::Msg<E, L, D>>, mpsc::error::SendError<_>>
        };
        
        round_based::MpcParty::connected((dkg_incoming, dkg_outgoing))
    };

    let incomplete_key_share =
        cggmp21::keygen::<E>(eid, i.try_into().expect("Can not parse id"), n)
            .set_threshold(t)
            .start(&mut OsRng, dkg_party)
            .await?;

    info!("DKG completed");

    let key_share = cggmp21::KeyShare::from_parts((incomplete_key_share, aux_info))?;

    info!("Key share generated");
    
    // Signing party adapter
    let sign_party = {
        // Create an adapter that filters for Signing messages
        let sign_incoming = {
            let rx = incoming_tx.subscribe();
            let stream = futures::stream::unfold(rx, |mut rx| async move {
                match rx.recv().await {
                    Ok(msg) => {
                        let filtered_msg = match msg {
                            Ok(incoming_msg) => {
                                if let UnifiedMsg::Signing(sign_msg) = incoming_msg.msg {
                                    Some(Ok(round_based::Incoming {
                                        sender: incoming_msg.sender,
                                        id: incoming_msg.id,
                                        msg_type: incoming_msg.msg_type,
                                        msg: sign_msg,
                                    }))
                                } else {
                                    None
                                }
                            },
                            Err(e) => Some(Err(e)),
                        };
                        Some((filtered_msg, rx))
                    },
                    Err(_) => Some((None, rx)), // Broadcast error
                }
            }).filter_map(|x| async move { x });
            Box::pin(stream) as BoxStream<'static, Result<Incoming<_>, CustomError>>
        };
        
        // Create an adapter for outgoing Signing messages
        let sign_outgoing = {
            let outgoing_tx = outgoing_tx.clone();
            
            let sink = futures::sink::unfold((), move |_, msg: Outgoing<cggmp21::signing::msg::Msg<E, D>>| {
                let outgoing_tx = outgoing_tx.clone();
                async move {
                    let unified_msg = Outgoing {
                        recipient: msg.recipient,
                        msg: UnifiedMsg::Signing(msg.msg),
                    };
                    let cloned_msg = unified_msg.clone();
                    
                    outgoing_tx.send(unified_msg).await
                        .map_err(|_| mpsc::error::SendError(cloned_msg))
                        .map(|_| ())
                }
            });
            
            Box::pin(sink) as BoxSink<'static, Outgoing<cggmp21::signing::msg::Msg<E, D>>, mpsc::error::SendError<_>>
        };
        
        round_based::MpcParty::connected((sign_incoming, sign_outgoing))
    };
    
    // Define the parties that participated in key generation
    let parties_indexes_at_keygen = vec![i as u16];
    
    let data_to_sign = cggmp21::DataToSign::digest::<D>(b"data to be signed");
    
    info!("Signing data");
    let signature = cggmp21::signing(eid, i as u16, &parties_indexes_at_keygen, &key_share)
        .sign(&mut OsRng, sign_party, data_to_sign)
        .await?;
    info!("Signature: {:?}", signature);
    Ok(())
}
