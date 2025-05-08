use anyhow::{Context as AnyhowContext, Result};
use futures::SinkExt;
use futures_channel::mpsc;
use round_based::{Incoming, MessageDestination, Outgoing};
use serde::Serialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{RwLock, mpsc as tokio_mpsc},
};

/// Creates a communication channel for a TCP stream
fn create_stream_channel<M>(
    stream: TcpStream,
) -> (tokio::io::ReadHalf<TcpStream>, tokio_mpsc::Sender<M>)
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

/// Handle messages received from a TCP stream
async fn handle_messages<M>(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    address: SocketAddr,
    peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
    incoming_tx: mpsc::Sender<Incoming<M>>,
) where
    M: Send + 'static + for<'de> serde::de::Deserialize<'de>,
{
    let mut buffer = [0u8; 1024];
    let mut incoming_tx = incoming_tx;

    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                if let Ok(msg) = bincode::deserialize::<M>(&buffer[..n]) {
                    println!("+++++ Received message from {:?}", address);

                    let sender_id = find_peer_id(&peers_id, address).await;
                    let incoming_msg = Incoming {
                        id: 0,
                        sender: sender_id,
                        msg_type: round_based::MessageType::Broadcast,
                        msg,
                    };
                    if incoming_tx.send(incoming_msg).await.is_err() {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
}

/// Find peer ID corresponding to an address
async fn find_peer_id(
    peers_id: &Arc<RwLock<HashMap<u16, SocketAddr>>>,
    address: SocketAddr,
) -> u16 {
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
    peers: Arc<RwLock<HashMap<SocketAddr, tokio::sync::mpsc::Sender<M>>>>,
    peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
) -> Result<()>
where
    M: Send + 'static + for<'de> serde::de::Deserialize<'de> + Serialize,
{
    let stream = TcpStream::connect(address)
        .await
        .with_context(|| format!("Failed to connect to {}", address))?;

    let (reader, tx) = create_stream_channel(stream);
    peers.write().await.insert(address, tx);

    // Clone Arc before moving it into the task
    let peers_id_clone = peers_id.clone();
    tokio::spawn(async move {
        handle_messages(reader, address, peers_id_clone, incoming_tx).await;
    });

    Ok(())
}

pub async fn handle_connection<'a, M>(
    stream: TcpStream,
    address: SocketAddr,
    incoming_tx: mpsc::Sender<Incoming<M>>,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio::sync::mpsc::Sender<M>>>>,
    peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
) where
    M: Send + 'static + for<'de> serde::de::Deserialize<'de> + Serialize,
{
    let (reader, tx) = create_stream_channel(stream);
    peers.write().await.insert(address, tx);

    // Clone Arc before moving it into task
    let peers_id_clone = peers_id.clone();
    handle_messages(reader, address, peers_id_clone, incoming_tx).await;

    peers.write().await.remove(&address);
}

pub async fn handle_outgoing<M>(
    outgoing: Outgoing<M>,
    peers: &Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<M>>>>,
    peers_id: &Arc<RwLock<HashMap<u16, SocketAddr>>>,
) -> Result<()>
where
    M: Send + Sync + Clone + 'static,
{
    println!("----- Sending message to: {:?}", outgoing.recipient);

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
        if let Err(e) = receiver.send(outgoing.msg.clone()).await {
            eprintln!("Failed to send message: {}", e);
        }
    }

    Ok(())
}
