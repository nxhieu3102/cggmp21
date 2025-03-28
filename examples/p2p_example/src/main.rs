mod config;
mod handlers;
mod node;

use anyhow::Result;
use config::load_config;
use futures::StreamExt;
use node::Node;
use rand::rngs::OsRng;

type E = generic_ec::curves::Secp256k1;
type D = sha2::Sha256;
type L = cggmp21::security_level::SecurityLevel128;

#[tokio::main]
async fn main() -> Result<()> {
    // get config
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --bin p2p_example <config file>");
        return Ok(());
    }

    let config = load_config(&args[1])?;

    // set up network
    let (node, mut incoming, mut outgoing) =
        Node::<cggmp21::keygen::msg::threshold::Msg<E, L, D>>::new(config.node.address).await?;

    for peer in config.peers {
        if peer.id < config.node.id {
            if let Err(e) = node.connect(peer.address).await {
                eprintln!("Error connecting to peer: {}", e);
            } else {
                println!("Connected to peer: {}", peer.address);
            }
        }
    }

    // sleep for 10 seconds to allow all nodes to start
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // set up MPC
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
    Ok(())
}
