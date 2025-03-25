// An example from libp2p crate about stream protocol
// This example has been modified to connect new peers by providing their multiaddress from stdin
// -------------
// Open and run this application on some terminals: `cargo run --example cli_cggmp21`
// Each terminal will have a peer address printed on the console
// While the application is running, you can provide a multiaddress to connect to a new peer
// For example: `/ip4/127.0.0.1/udp/47123/quic-v1/p2p/12D3KooWAKSbXPjF9MauhLCpY9VKVaNcoD5HH9AuorM375pnDHb`
// -------------
// The crates used in this example are defined in the `cggmp21/Cargo.toml` file

use anyhow::Result;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId, Stream, StreamProtocol};
use libp2p_stream as stream;
use rand::RngCore;
use std::time::Duration;
use tokio::{io, io::AsyncBufReadExt, select};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

const ECHO_PROTOCOL: StreamProtocol = StreamProtocol::new("/echo");

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env()?,
        )
        .init();

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| stream::Behaviour::new())?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(15)))
        .build();

    swarm.listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse()?)?;

    let mut incoming_streams = swarm
        .behaviour()
        .new_control()
        .accept(ECHO_PROTOCOL)
        .unwrap();

    // Deal with incoming streams.
    // Spawning a dedicated task is just one way of doing this.
    // libp2p doesn't care how you handle incoming streams but you _must_ handle them somehow.
    // To mitigate DoS attacks, libp2p will internally drop incoming streams if your application
    // cannot keep up processing them.
    tokio::spawn(async move {
        // This loop handles incoming streams _sequentially_ but that doesn't have to be the case.
        // You can also spawn a dedicated task per stream if you want to.
        // Be aware that this breaks backpressure though as spawning new tasks is equivalent to an
        // unbounded buffer. Each task needs memory meaning an aggressive remote peer may
        // force you OOM this way.

        while let Some((peer, stream)) = incoming_streams.next().await {
            match echo(stream).await {
                Ok(n) => {
                    tracing::info!(%peer, "Echoed {n} bytes!");
                }
                Err(e) => {
                    tracing::warn!(%peer, "Echo failed: {e}");
                    continue;
                }
            };
        }
    });

    // User can add a peer address (from stdin) to dial while the application is running
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    loop {
        select! {

            Ok(Some(line)) = stdin.next_line() => {
                let maybe_address = match line.parse::<Multiaddr>() {
                    Ok(addr) => Some(addr),
                    Err(e) => return Err(anyhow::anyhow!("Failed to parse input as `Multiaddr`: {e}")),
                };

                if let Some(address) = maybe_address {
                    tracing::info!(%address, "Dialing peer...");
                    let Some(Protocol::P2p(peer_id)) = address.iter().last() else {
                        anyhow::bail!("Provided address does not end in `/p2p`");
                    };

                    swarm.dial(address)?;

                    tokio::spawn(connection_handler(peer_id, swarm.behaviour().new_control()));
                }
            }

            event = swarm.select_next_some() => match event {
                libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                    let listen_address = address.with_p2p(*swarm.local_peer_id()).unwrap();
                    tracing::info!(%listen_address);
                }
                event => tracing::trace!(?event),
            }
        }
    }
}

/// A very simple, `async fn`-based connection handler for our custom echo protocol.
async fn connection_handler(peer: PeerId, mut control: stream::Control) {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await; // Wait a second between echos.

        let stream = match control.open_stream(peer, ECHO_PROTOCOL).await {
            Ok(stream) => stream,
            Err(error @ stream::OpenStreamError::UnsupportedProtocol(_)) => {
                tracing::info!(%peer, %error);
                return;
            }
            Err(error) => {
                // Other errors may be temporary.
                // In production, something like an exponential backoff / circuit-breaker may be
                // more appropriate.
                tracing::debug!(%peer, %error);
                continue;
            }
        };

        if let Err(e) = send(stream).await {
            tracing::warn!(%peer, "Echo protocol failed: {e}");
            continue;
        }

        tracing::info!(%peer, "Echo complete!")
    }
}

async fn echo(mut stream: Stream) -> io::Result<usize> {
    let mut total = 0;

    let mut buf = [0u8; 100];

    loop {
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            return Ok(total);
        }

        total += read;
        stream.write_all(&buf[..read]).await?;
    }
}

async fn send(mut stream: Stream) -> io::Result<()> {
    let num_bytes = rand::random::<usize>() % 1000;

    let mut bytes = vec![0; num_bytes];
    rand::thread_rng().fill_bytes(&mut bytes);

    stream.write_all(&bytes).await?;

    let mut buf = vec![0; num_bytes];
    stream.read_exact(&mut buf).await?;

    if bytes != buf {
        return Err(io::Error::new(io::ErrorKind::Other, "incorrect echo"));
    }

    stream.close().await?;

    Ok(())
}
