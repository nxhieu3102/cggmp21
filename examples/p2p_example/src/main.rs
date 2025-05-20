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
use futures::SinkExt;
use node::Node;
use round_based::Outgoing;
use std::time::Duration;

// Define types for the cryptographic primitives
type E = generic_ec::curves::Secp256k1;
type D = sha2::Sha256;
type L = cggmp21::security_level::SecurityLevel128;

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
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --bin p2p_example <config file>");
        return Ok(());
    }

    // Load the node configuration
    let config =
        load_config(&args[1]).context(format!("Failed to load config from {}", &args[1]))?;

    // Set up the P2P network
    println!("Initializing P2P network node...");
    let (node, _incoming, mut outgoing) = Node::<Msg<E, L, D>>::new(config).await?;

    // Wait for all nodes to start and connect
    sleep_with_message(
        Duration::from_secs(10),
        "Sleeping for 10 seconds to allow all nodes to start...",
    )
    .await;

    // Display node information for debugging
    display_node_info(&node).await;

    // Send a test message to all peers
    let test_message = cggmp21::keygen::msg::threshold::MsgRound1 {
        commitment: sha2::digest::generic_array::GenericArray::default(),
    };

    println!("Sending test message to all peers...");
    outgoing
        .send(Outgoing::broadcast(Msg::Round1(test_message)))
        .await
        .context("Failed to send broadcast message")?;

    // Wait to receive messages from other peers
    sleep_with_message(
        Duration::from_secs(10),
        "Sleeping for 10 seconds to receive messages...",
    )
    .await;

    // Uncomment to enable the actual DKG protocol
    
    // Set up MPC
    let delivery = (
        incoming.map(|msg| msg.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))),
        outgoing,
    );
    let party = round_based::MpcParty::connected(delivery);

    // DKG
    let eid = cggmp21::ExecutionId::new(b"execution id, unique per protocol execution");
    let i = config.node.id - 1;
    let n = 3;
    let t = 2;

    println!("Starting DKG with id: {}, n: {}, t: {}", i, n, t);

    let _incomplete_key_share =
        cggmp21::keygen::<E>(eid, i.try_into().expect("Can not parse id"), n)
            .set_threshold(t)
            .start(&mut OsRng, party)
            .await?;

    tokio::signal::ctrl_c().await?;
    

    println!("P2P example completed successfully");
    Ok(())
}
