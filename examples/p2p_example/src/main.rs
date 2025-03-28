// cargo run --bin p2p_example test-data/p2p_example/dkg/node1.yaml
// cargo run --bin p2p_example test-data/p2p_example/dkg/node2.yaml
// cargo run --bin p2p_example test-data/p2p_example/dkg/node3.yaml
// -------------
use anyhow::Result;
use futures::{Sink, SinkExt, Stream, StreamExt};
use futures_channel::mpsc;
use std::sync::Arc;
use std::{collections::HashMap, net::SocketAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{RwLock, mpsc as tokio_mpsc},
};

// Message types
#[derive(Debug, Clone)]
pub struct Msg {
    content: String,
    from: SocketAddr,
}

#[derive(Debug)]
pub struct Incoming<T> {
    pub msg: T,
    pub from: SocketAddr,
}

#[derive(Debug)]
pub struct Outgoing<T> {
    pub msg: T,
    pub to: SocketAddr,
}

// P2P Node structure
pub struct Node {
    address: SocketAddr,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<Msg>>>>,
}

impl Node {
    pub async fn new(
        address: SocketAddr,
    ) -> Result<(
        Self,
        impl Stream<Item = Result<Incoming<Msg>>>,
        impl Sink<Outgoing<Msg>, Error = mpsc::SendError>,
    )> {
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let (incoming_tx, incoming_rx) = mpsc::channel(32);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(32);

        let node = Node {
            address,
            peers: peers.clone(),
        };

        // Start TCP listener
        let listener = TcpListener::bind(address).await?;
        let peers_clone = peers.clone();

        // Handle incoming connections
        tokio::spawn(async move {
            while let Ok((stream, address)) = listener.accept().await {
                handle_connection(stream, address, incoming_tx.clone(), peers_clone.clone()).await;
            }
        });

        // Handle outgoing messages
        tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.next().await {
                if let Err(e) = handle_outgoing(msg, &peers).await {
                    eprintln!("Error sending message: {}", e);
                }
            }
        });

        Ok((node, incoming_rx.map(Ok), outgoing_tx))
    }

    pub async fn connect(&self, address: SocketAddr) -> Result<()> {
        let stream = TcpStream::connect(address).await?;
        let (tx, mut rx) = tokio_mpsc::channel(32);
        self.peers.write().await.insert(address, tx);

        // Set up message forwarding from channel to TCP
        let (mut reader, mut writer) = tokio::io::split(stream);

        // Forward messages from rx channel to the TCP connection
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                // In a real implementation, you'd serialize the message
                if let Err(e) = writer.write_all(msg.content.as_bytes()).await {
                    eprintln!("Error writing to TCP stream: {}", e);
                    break;
                }
                if let Err(e) = writer.flush().await {
                    eprintln!("Error flushing TCP stream: {}", e);
                    break;
                }
            }
        });

        // A real implementation would also set up a reader for bidirectional communication
        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    address: SocketAddr,
    incoming_tx: mpsc::Sender<Incoming<Msg>>,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<Msg>>>>,
) {
    // Split the TCP stream
    let (mut reader, mut writer) = tokio::io::split(stream);

    // Create a channel for this peer
    let (tx, _rx) = tokio_mpsc::channel::<Msg>(32);
    peers.write().await.insert(address, tx);

    // Read from TCP and forward to internal messaging
    let mut buffer = [0u8; 1024];
    let mut incoming_tx = incoming_tx;

    tokio::spawn(async move {
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    // Connection closed
                    println!("Connection closed by peer: {}", address);
                    break;
                }
                Ok(n) => {
                    // Convert bytes to string
                    if let Ok(content) = String::from_utf8(buffer[..n].to_vec()) {
                        let msg = Msg {
                            content,
                            from: address,
                        };
                        let incoming = Incoming { msg, from: address };
                        if let Err(e) = incoming_tx.send(incoming).await {
                            eprintln!("Failed to forward message internally: {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from TCP stream: {}", e);
                    break;
                }
            }
        }
        // Remove peer when connection ends
        peers.write().await.remove(&address);
    });
}

async fn handle_outgoing(
    outgoing: Outgoing<Msg>,
    peers: &Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<Msg>>>>,
) -> Result<()> {
    if let Some(peer) = peers.read().await.get(&outgoing.to) {
        peer.send(outgoing.msg)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send message: {}", e))?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Check command line args to determine which node to run
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --bin p2p_example <config file>");
        eprintln!("Example: cargo run --bin p2p_example test-data/p2p_example/dkg/node1.yaml");
        return Ok(());
    }

    let config_file = args[1].as_str();
    let config = load_config(config_file)?;

    run_node(config).await
}

// config file format
#[derive(serde::Deserialize)]
struct Config {
    node: NodeConfig,
    peers: Vec<PeerConfig>,
}

#[derive(serde::Deserialize)]
struct NodeConfig {
    id: usize,
    address: SocketAddr,
}

#[derive(serde::Deserialize)]
struct PeerConfig {
    id: usize,
    address: SocketAddr,
}

fn load_config(config_file: &str) -> Result<Config> {
    let config = std::fs::read_to_string(config_file)?;
    let config: Config = serde_yaml::from_str(&config)?;
    Ok(config)
}

// Run a single node
async fn run_node(config: Config) -> Result<()> {
    println!(
        "Starting node {} on {}",
        config.node.id, config.node.address
    );
    let (node, mut incoming, mut outgoing) = Node::new(config.node.address).await?;

    // INTEGRATION WITH ROUND_BASED PROTOCOL
    // To use this p2p setup with the CGGMP21 protocols, you would need to:
    // 1. Create adapters from our Incoming/Outgoing to round_based::Incoming/Outgoing
    // 2. Connect them with MpcParty:
    //
    // let party = round_based::MpcParty::connected((
    //    adapter_for_incoming_stream,
    //    adapter_for_outgoing_sink
    // ));`
    //
    // 3. Then use the party with protocols from the cggmp21 library
    // e.g.: cggmp21::signing(eid, i, &parties_indexes_at_keygen, &key_share)
    //         .sign(&mut OsRng, party, data_to_sign)
    //         .await?;

    // Give other nodes time to start before trying to connect
    println!("Waiting 5 seconds before connecting to other nodes...");
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    for peer in config.peers {
        // only connect to peers with lower address
        // advoid 2 nodes connecting to each other
        if peer.id >= config.node.id {
            continue;
        }

        println!("Connecting to peer {} at {}", peer.id, peer.address);

        if let Err(e) = node.connect(peer.address).await {
            eprintln!("Failed to connect to peer: {}", e);
        } else {
            println!("Connected to peer!");

            // Send message to that node
            let msg = Outgoing {
                msg: Msg {
                    content: format!("Hello from node {}!", config.node.id),
                    from: config.node.address,
                },
                to: peer.address,
            };

            println!("Sending message to node {}: {}", peer.id, msg.msg.content);
            if let Err(e) = outgoing.send(msg).await {
                eprintln!("Failed to send message: {}", e);
            } else {
                println!("Message sent successfully!");
            }
        }
    }

    // Also listen for incoming messages
    tokio::spawn(async move {
        println!("Listening for incoming messages...");
        while let Some(Ok(incoming)) = incoming.next().await {
            println!("Node {} received: {:?}", config.node.id, incoming.msg);
        }
    });

    // Keep the main thread running
    println!("Press Ctrl+C to exit");
    tokio::signal::ctrl_c().await?;
    Ok(())
}
