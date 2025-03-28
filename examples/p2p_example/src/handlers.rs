use crate::message::{Incoming, Msg, Outgoing};
use anyhow::Result;
use futures::SinkExt;
use futures_channel::mpsc;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{io::AsyncReadExt, net::TcpStream, sync::RwLock};

pub async fn handle_connection(
    mut stream: TcpStream,
    address: SocketAddr,
    incoming_tx: mpsc::Sender<Incoming<Msg>>,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio::sync::mpsc::Sender<Msg>>>>,
) {
    let (tx, _rx) = tokio::sync::mpsc::channel(32);
    peers.write().await.insert(address, tx);

    let mut incoming_tx = incoming_tx;
    let mut buffer = [0u8; 1024];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => {
                if let Ok(content) = String::from_utf8(buffer[..n].to_vec()) {
                    let msg = Msg {
                        content,
                        from: address,
                    };
                    if incoming_tx
                        .send(Incoming { msg, from: address })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }

    peers.write().await.remove(&address);
}

pub async fn handle_outgoing(
    outgoing: Outgoing<Msg>,
    peers: &Arc<RwLock<HashMap<SocketAddr, tokio::sync::mpsc::Sender<Msg>>>>,
) -> Result<()> {
    if let Some(peer) = peers.read().await.get(&outgoing.to) {
        peer.send(outgoing.msg).await?;
    }
    Ok(())
}
