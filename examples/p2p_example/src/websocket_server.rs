use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};

type PeerMap = Arc<Mutex<HashMap<SocketAddr, (u16, futures_channel::mpsc::UnboundedSender<Message>)>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a shared state for connected peers
    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));

    // Bind to the WebSocket server address
    let addr = "127.0.0.1:8080";
    let listener = TcpListener::bind(addr).await?;
    println!("WebSocket server listening on: {}", addr);

    while let Ok((stream, addr)) = listener.accept().await {
        println!("New connection from: {}", addr);
        tokio::spawn(handle_connection(peers.clone(), stream, addr));
    }

    Ok(())
}

async fn handle_connection(peer_map: PeerMap, stream: TcpStream, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let ws_stream = accept_async(stream).await?;
    println!("WebSocket connection established: {}", addr);

    let (tx, rx) = futures_channel::mpsc::unbounded();
    
    // Split the WebSocket stream
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Add the new peer to our map with a default party ID of 0
    {
        let mut peers = peer_map.lock().unwrap();
        peers.insert(addr, (0, tx));
    }

    // Forward received messages from this WebSocket to all peers
    tokio::spawn(async move {
        while let Some(msg) = rx.next().await {
            if let Err(e) = ws_sender.send(msg).await {
                eprintln!("Error sending WebSocket message: {}", e);
                break;
            }
        }
    });

    // Process incoming WebSocket messages
    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(msg) => {
                println!("Received message from {}: {:?}", addr, msg);
                
                // Parse message (assume format "PARTY_ID:MESSAGE" for registration)
                if let Message::Text(text) = &msg {
                    if text.starts_with("REGISTER:") {
                        if let Some(party_id_str) = text.strip_prefix("REGISTER:") {
                            if let Ok(party_id) = party_id_str.trim().parse::<u16>() {
                                // Update party ID in peer map
                                let mut peers = peer_map.lock().unwrap();
                                if let Some((id, _)) = peers.get_mut(&addr) {
                                    *id = party_id;
                                    println!("Client {} registered as party {}", addr, party_id);
                                    
                                    // Send confirmation
                                    let confirm_msg = Message::Text(format!("Registered as party {}", party_id));
                                    if let Some((_, sender)) = peers.get(&addr) {
                                        let _ = sender.unbounded_send(confirm_msg);
                                    }
                                }
                            }
                        }
                    } else {
                        // Broadcast message to all peers
                        broadcast_message(&peer_map, &addr, msg).await;
                    }
                } else {
                    // For binary or other message types, just broadcast
                    broadcast_message(&peer_map, &addr, msg).await;
                }
            }
            Err(e) => {
                eprintln!("WebSocket error: {}", e);
                break;
            }
        }
    }

    // Remove disconnected peer
    {
        let mut peers = peer_map.lock().unwrap();
        peers.remove(&addr);
    }
    
    println!("Connection closed: {}", addr);
    Ok(())
}

async fn broadcast_message(peer_map: &PeerMap, sender_addr: &SocketAddr, msg: Message) {
    if let Ok(peer_map) = peer_map.lock() {
        let sender_id = peer_map.get(sender_addr).map(|(id, _)| *id).unwrap_or(0);
        
        // Add sender ID to message if it's text
        let broadcast_msg = if let Message::Text(text) = msg {
            Message::Text(format!("FROM_PARTY_{}:{}", sender_id, text))
        } else {
            msg
        };
        
        for (addr, (_, tx)) in peer_map.iter() {
            if addr != sender_addr {  // Don't send back to sender
                if let Err(e) = tx.unbounded_send(broadcast_msg.clone()) {
                    eprintln!("Error broadcasting message to {}: {}", addr, e);
                }
            }
        }
    }
} 
