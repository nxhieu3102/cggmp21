use p2p_network::{
    create_node_builder, 
    message::InternalMessage,
    native::{
        transport::TcpTransportAdapter,
        network::TcpNetworkImpl,
        handler::BasicMessageHandler,
    },
    key::NativeKeyManager,
    config::FileConfigLoader,
    KeyManager,
    node::NodeBuilder,
};
use std::path::PathBuf;
use futures::StreamExt;
use std::time::Duration;
use std::thread;
use tokio::runtime::Runtime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    p2p_network::init_logger();
    
    println!("Creating P2P node...");
    
    // Create transport and network layer
    let transport = TcpTransportAdapter::<InternalMessage>::new("127.0.0.1:8000");
    let network = TcpNetworkImpl::with_transport(transport);
    
    // Create key manager
    let mut key_manager = NativeKeyManager::new();
    key_manager.generate_keypair()?;
    
    // Create config
    let config = FileConfigLoader::new(PathBuf::from("node_config.yaml"));
    
    // Create message handler
    let handler = BasicMessageHandler::<InternalMessage>::new();
    
    // Build node - using concrete types explicitly instead of impl traits
    let mut node = NodeBuilder::<
        TcpNetworkImpl<InternalMessage>,
        NativeKeyManager,
        FileConfigLoader,
        BasicMessageHandler<InternalMessage>,
        InternalMessage
    >::new()
        .with_id("node-1".to_string())
        .with_network(network)
        .with_key_manager(key_manager)
        .with_config(config)
        .with_handler(handler)
        .build()?;
    
    // Get event stream before starting the node
    let mut events = node.events().expect("Failed to get event stream");
    
    // Start node
    println!("Starting node...");
    node.start()?;
    
    // Spawn a task to process events
    let event_task = tokio::spawn(async move {
        println!("Listening for events...");
        while let Some(event) = events.next().await {
            println!("Event: {:?}", event);
        }
        println!("Event stream ended");
    });
    
    // Optionally connect to another peer
    if std::env::args().len() > 1 {
        let peer_address = std::env::args().nth(1).unwrap();
        println!("Connecting to peer at {}", peer_address);
        match node.connect(&peer_address) {
            Ok(peer_id) => {
                println!("Connected to peer: {}", peer_id);
                
                // Send a test message
                let node_id = node.id.as_ref().map_or("unknown", |id| id.as_str());
                let message = InternalMessage::new("hello", Some(node_id), vec![1, 2, 3]);
                if let Err(e) = node.send_to(&peer_id, message) {
                    println!("Failed to send message: {}", e);
                } else {
                    println!("Message sent to peer: {}", peer_id);
                }
            },
            Err(e) => println!("Failed to connect: {}", e),
        }
    }
    
    // Keep the node running
    println!("Node running. Press Ctrl+C to exit...");
    
    // Wait for Ctrl+C
    #[cfg(feature = "native")]
    {
        ctrlc::set_handler(move || {
            println!("Received Ctrl+C, shutting down...");
            std::process::exit(0);
        }).expect("Error setting Ctrl+C handler");
    }
    
    // Create a loop to keep the program running
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        // Print connected peers every second
        println!("Connected peers: {:?}", node.connected_peers());
    }
    
    // The following code won't be reached due to the loop above
    #[allow(unreachable_code)]
    {
        // Stop the node
        node.stop()?;
        
        // Wait for event task to finish
        let _ = event_task.await;
        
        println!("Node stopped");
    }
    
    Ok(())
} 
