use anyhow::Result;
use futures::{Sink, SinkExt, Stream, StreamExt};
use futures_channel::mpsc;
use round_based::{Incoming, Outgoing};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{RwLock, mpsc as tokio_mpsc},
};

pub struct Node<M> {
    address: SocketAddr,
    peers: Arc<RwLock<HashMap<SocketAddr, tokio_mpsc::Sender<M>>>>,
}

impl<M> Node<M>
where
    M: serde::Serialize + Send + 'static,
{
    pub async fn new(
        address: SocketAddr,
    ) -> Result<(
        Self,
        impl Stream<Item = Result<Incoming<M>>>,
        impl Sink<Outgoing<M>, Error = mpsc::SendError>,
    )> {
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let (incoming_tx, incoming_rx) = mpsc::channel(32);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(32);

        let node = Node {
            address,
            peers: peers.clone(),
        };

        let listener = TcpListener::bind(address).await?;
        let peers_clone = peers.clone();

        tokio::spawn(async move {
            while let Ok((stream, address)) = listener.accept().await {
                println!("Incoming connection from: {}", address);
                // super::handlers::handle_connection(
                //     stream,
                //     address,
                //     incoming_tx.clone(),
                //     peers_clone.clone(),
                // )
                // .await;
            }
        });

        tokio::spawn(async move {
            while let Some(_msg) = outgoing_rx.next().await {
                println!("Sending some messages");
                // if let Err(e) = super::handlers::handle_outgoing(msg, &peers).await {
                //     eprintln!("Error sending message: {}", e);
                // }
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
