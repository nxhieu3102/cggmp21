use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Msg {
    pub content: String,
    pub from: SocketAddr,
}

#[derive(Debug)]
pub struct Incoming<T> {
    pub msg: T,
    pub from: SocketAddr,
}

#[derive(Debug)]
pub struct Outgoing<T> {
    pub msg: T,
    pub to: SocketAddr,
}
