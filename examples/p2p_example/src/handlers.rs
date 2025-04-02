use anyhow::Result;
use futures::SinkExt;
use futures_channel::mpsc;
use round_based::{Incoming, MessageDestination, Outgoing};
use serde::Serialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, vec};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{RwLock, mpsc as tokio_mpsc},
};

pub async fn connect<M>(
    address: SocketAddr,
    incoming_tx: mpsc::Sender<Incoming<M>>,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio::sync::mpsc::Sender<M>>>>,
    peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
) -> Result<()>
where
    M: Send + 'static + for<'de> serde::de::Deserialize<'de> + Serialize,
{
    let mut incoming_tx = incoming_tx;
    let stream = TcpStream::connect(address).await?;
    let (tx, mut rx) = tokio_mpsc::channel(32);
    peers.write().await.insert(address, tx);

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

    tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(msg) = bincode::deserialize::<M>(&buffer[..n]) {
                        println!("+++++ Received message from {:?}", address);
                        let incoming_msg = Incoming {
                            id: 0,
                            sender: // peer id correspoding to the address
                                peers_id
                                    .read()
                                    .await
                                    .iter()
                                    .find(|(_, addr)| **addr == address)
                                    .map(|(id, _)| *id)
                                    .unwrap_or(0),
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
    });

    Ok(())
}

pub async fn handle_connection<'a, M>(
    mut stream: TcpStream,
    address: SocketAddr,
    incoming_tx: mpsc::Sender<Incoming<M>>,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio::sync::mpsc::Sender<M>>>>,
    peers_id: Arc<RwLock<HashMap<u16, SocketAddr>>>,
) where
    M: Send + 'static + for<'de> serde::de::Deserialize<'de> + Serialize,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel(32);
    peers.write().await.insert(address, tx);

    let mut incoming_tx = incoming_tx;
    let mut buffer = [0u8; 1024];
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

    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                if let Ok(msg) = bincode::deserialize::<M>(&buffer[..n]) {
                    println!("+++++ Received message from {:?}", address);

                    let incoming_msg = Incoming {
                        id: 0,
                        sender: // peer id correspoding to the address
                            peers_id
                                .read()
                                .await
                                .iter()
                                .find(|(_, addr)| **addr == address)
                                .map(|(id, _)| *id)
                                .unwrap_or(0),
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

    peers.write().await.remove(&address);
}

pub async fn handle_outgoing<M>(
    // add self id
    outgoing: Outgoing<M>,
    peers: &Arc<RwLock<HashMap<SocketAddr, tokio::sync::mpsc::Sender<M>>>>,
    peers_id: &Arc<RwLock<HashMap<u16, SocketAddr>>>,
) -> Result<()>
where
    M: Send + Sync + Clone + 'static,
{
    println!("----- Sending some messages to: {:?}", outgoing.recipient);

    let receivers = match outgoing.recipient {
        MessageDestination::AllParties => peers.read().await.values().cloned().collect::<Vec<_>>(),
        MessageDestination::OneParty(peer_id) => {
            if let Some(peer_address) = peers_id.read().await.get(&peer_id) {
                if let Some(receiver) = peers.read().await.get(peer_address) {
                    vec![receiver.clone()]
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        }
    };

    for receiver in receivers {
        if let Err(_e) = receiver.send(outgoing.msg.clone()).await {
            eprintln!("Failed to send message");
        }
    }

    Ok(())
}
