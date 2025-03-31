use anyhow::Result;
use futures::{Sink, Stream, StreamExt};
use futures_channel::mpsc;
use round_based::{Incoming, Outgoing};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{RwLock, mpsc as tokio_mpsc},
};

use crate::config;

pub struct Node<M> {
    address: SocketAddr,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<M>>>>,
    peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
}

impl<M> Node<M>
where
    M: Send + Sync + Clone + 'static + Serialize + for<'de> serde::de::Deserialize<'de>,
{
    pub async fn new(
        address: &SocketAddr,
        config: &config::Config,
    ) -> Result<(
        Self,
        impl Stream<Item = Result<Incoming<M>>>,
        impl Sink<Outgoing<M>, Error = mpsc::SendError>,
    )> {
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let (incoming_tx, incoming_rx) = mpsc::channel(32);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(32);

        let peers_id = Arc::new(RwLock::new(HashMap::new()));
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
            address: address.clone(),
            peers: peers.clone(),
            peers_id: peers_id.clone(),
        };

        let listener = TcpListener::bind(address).await?;
        let peers_clone = peers.clone();
        let peers_id_clone = peers_id.clone();

        tokio::spawn(async move {
            while let Ok((stream, address)) = listener.accept().await {
                println!("Incoming connection from: {}", address);
                super::handlers::handle_connection(
                    stream,
                    address,
                    incoming_tx.clone(),
                    peers_clone.clone(),
                    peers_id_clone.clone(),
                )
                .await;
            }
        });

        tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.next().await {
                println!("Sending some messages");
                if let Err(e) = super::handlers::handle_outgoing(msg, &peers, &peers_id).await {
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

        let (mut reader, mut writer) = tokio::io::split(stream);

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

        Ok(())
    }
}
