use anyhow::Result;
use futures::{Sink, Stream, StreamExt};
use futures_channel::mpsc;
use round_based::{Incoming, Outgoing};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    net::TcpListener,
    sync::{RwLock, mpsc as tokio_mpsc},
};

use crate::{config, handlers::connect};

pub struct Node<M> {
    pub address: SocketAddr,
    pub peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<M>>>>,
    pub peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
}

impl<M> Node<M>
where
    M: Send + Sync + Clone + 'static + Serialize + for<'de> serde::de::Deserialize<'de>,
{
    pub async fn new(
        config: config::Config,
    ) -> Result<(
        Self,
        impl Stream<Item = Result<Incoming<M>>>,
        impl Sink<Outgoing<M>, Error = mpsc::SendError>,
    )> {
        let (incoming_tx, incoming_rx) = mpsc::channel(32);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(32);

        let peers = Arc::new(RwLock::new(HashMap::new()));
        let peers_id = Arc::new(RwLock::new(HashMap::new()));

        // Build map: <peer_id, address>
        peers_id
            .write()
            .await
            .insert(config.node.id.try_into().unwrap(), config.node.address);
        for peer in config.peers.iter() {
            peers_id
                .write()
                .await
                .insert(peer.id.try_into().unwrap(), peer.address);
        }

        let node = Node {
            address: config.node.address,
            peers: peers.clone(),
            peers_id: peers_id.clone(),
        };

        let listener = TcpListener::bind(node.address).await?;

        // Accept incoming connections from other peers
        let peers_clone = peers.clone();
        let peers_id_clone = peers_id.clone();
        let incoming_tx_clone = incoming_tx.clone();
        tokio::spawn({
            let peers_clone = peers_clone.clone();
            let peers_id_clone = peers_id_clone.clone();
            let incoming_tx_clone = incoming_tx_clone.clone();
            async move {
                while let Ok((stream, address)) = listener.accept().await {
                    println!("Incoming connection from: {}", address);
                    let peers_clone = peers_clone.clone();
                    let peers_id_clone = peers_id_clone.clone();
                    let incoming_tx_clone = incoming_tx_clone.clone();
                    tokio::spawn(async move {
                        super::handlers::handle_connection(
                            stream,
                            address,
                            incoming_tx_clone,
                            peers_clone,
                            peers_id_clone,
                        )
                        .await;
                    });
                }
            }
        });

        // Connect to peers
        tokio::spawn(async move {
            for peer in config.peers.iter() {
                let peers_clone = peers_clone.clone();
                let peers_id_clone = peers_id_clone.clone();
                let incoming_tx_clone = incoming_tx_clone.clone();
                if peer.id < config.node.id {
                    if let Err(e) =
                        connect(peer.address, incoming_tx_clone, peers_clone, peers_id_clone).await
                    {
                        eprintln!("Error connecting to peer: {}", e);
                    } else {
                        println!("Connected to peer: {}", peer.address);
                    }
                }
            }
        });

        // Handle outgoing messages
        tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.next().await {
                if let Err(e) = super::handlers::handle_outgoing(msg, &peers, &peers_id).await {
                    eprintln!("Error sending message: {}", e);
                }
            }
        });

        Ok((node, incoming_rx.map(Ok), outgoing_tx))
    }
}
