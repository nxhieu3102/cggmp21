use futures::{SinkExt, StreamExt, Stream, Sink};
use futures_channel::mpsc;
use std::{collections::HashMap, net::SocketAddr};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{RwLock, mpsc as tokio_mpsc},
    io::{AsyncReadExt, AsyncWriteExt},
};
use anyhow::Result;
use std::sync::Arc;

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
    addr: SocketAddr,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<Msg>>>>,
}

impl Node {
    pub async fn new(addr: SocketAddr) -> Result<(Self, impl Stream<Item = Result<Incoming<Msg>>>, impl Sink<Outgoing<Msg>, Error = mpsc::SendError>)> {
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let (incoming_tx, incoming_rx) = mpsc::channel(32);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(32);

        let node = Node {
            addr,
            peers: peers.clone(),
        };

        // Start TCP listener
        let listener = TcpListener::bind(addr).await?;
        let peers_clone = peers.clone();

        // Handle incoming connections
        tokio::spawn(async move {
            while let Ok((stream, addr)) = listener.accept().await {
                handle_connection(stream, addr, incoming_tx.clone(), peers_clone.clone()).await;
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

    pub async fn connect(&self, addr: SocketAddr) -> Result<()> {
        let stream = TcpStream::connect(addr).await?;
        let (tx, mut rx) = tokio_mpsc::channel(32);
        self.peers.write().await.insert(addr, tx);
        
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
    addr: SocketAddr,
    incoming_tx: mpsc::Sender<Incoming<Msg>>,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<Msg>>>>,
) {
    // Split the TCP stream
    let (mut reader, mut writer) = tokio::io::split(stream);
    
    // Create a channel for this peer
    let (tx, _rx) = tokio_mpsc::channel::<Msg>(32);
    peers.write().await.insert(addr, tx);
    
    // Read from TCP and forward to internal messaging
    let mut buffer = [0u8; 1024];
    let mut incoming_tx = incoming_tx;
    
    tokio::spawn(async move {
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    // Connection closed
                    println!("Connection closed by peer: {}", addr);
                    break;
                }
                Ok(n) => {
                    // Convert bytes to string
                    if let Ok(content) = String::from_utf8(buffer[..n].to_vec()) {
                        let msg = Msg {
                            content,
                            from: addr,
                        };
                        let incoming = Incoming { msg, from: addr };
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
        peers.write().await.remove(&addr);
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
        eprintln!("Usage: cargo run --example p2p_example [1|2]");
        eprintln!("  1: Run as node 1 (listen on 127.0.0.1:8081)");
        eprintln!("  2: Run as node 2 (listen on 127.0.0.1:8082)");
        return Ok(());
    }

    match args[1].as_str() {
        "1" => run_node1().await,
        "2" => run_node2().await,
        _ => {
            eprintln!("Invalid argument. Use '1' or '2'.");
            Ok(())
        }
    }
}

async fn run_node1() -> Result<()> {
    let addr1 = "127.0.0.1:8081".parse()?;
    let addr2 = "127.0.0.1:8082".parse()?;
    
    println!("Starting node 1 on {}", addr1);
    let (node1, mut incoming1, mut outgoing1) = Node::new(addr1).await?;
    
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
    
    // Give node2 time to start before trying to connect
    println!("Waiting 2 seconds before connecting to node 2...");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    println!("Connecting to node 2 at {}", addr2);
    if let Err(e) = node1.connect(addr2).await {
        eprintln!("Failed to connect to node 2: {}", e);
    } else {
        println!("Connected to node 2!");
        
        // Send message to node 2
        let msg = Outgoing {
            msg: Msg {
                content: "Hello from node1!".to_string(),
                from: addr1,
            },
            to: addr2,
        };
        println!("Sending message to node 2: {}", msg.msg.content);
        if let Err(e) = outgoing1.send(msg).await {
            eprintln!("Failed to send message: {}", e);
        } else {
            println!("Message sent successfully!");
        }
    }

    // Also listen for incoming messages
    tokio::spawn(async move {
        println!("Listening for incoming messages...");
        while let Some(Ok(incoming)) = incoming1.next().await {
            println!("Node1 received: {:?}", incoming.msg);
        }
    });
    
    // Keep the main thread running
    println!("Press Ctrl+C to exit");
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn run_node2() -> Result<()> {
    let addr2 = "127.0.0.1:8082".parse()?;
    
    println!("Starting node 2 on {}", addr2);
    let (node2, mut incoming2, _outgoing2) = Node::new(addr2).await?;
    
    // Listen for incoming messages
    println!("Listening for incoming messages...");
    while let Some(Ok(incoming)) = incoming2.next().await {
        println!("Node2 received: {:?} from {}", incoming.msg.content, incoming.from);
    }
    
    Ok(())
} 
