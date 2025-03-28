mod config;
mod handlers;
mod message;
mod node;

use anyhow::Result;
use config::load_config;
use futures::StreamExt;
use node::Node;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --bin p2p_example <config file>");
        return Ok(());
    }

    let config = load_config(&args[1])?;
    let (node, mut incoming, mut outgoing) = Node::new(config.node.address).await?;

    for peer in config.peers {
        if peer.id < config.node.id {
            if let Err(e) = node.connect(peer.address).await {
                eprintln!("Error connecting to peer: {}", e);
            } else {
                println!("Connected to peer: {}", peer.address);
            }
        }
    }

    tokio::spawn(async move {
        while let Some(Ok(incoming)) = incoming.next().await {
            println!("Received: {:?}", incoming.msg);
        }
    });

    tokio::signal::ctrl_c().await?;
    Ok(())
}
