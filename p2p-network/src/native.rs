// Native (non-WASM) implementations
pub mod transport;
pub mod network;
pub mod handler;

/// Initialize native logger
pub fn init_native_logger() {
    #[cfg(feature = "native")]
    {
        use tracing_subscriber::fmt;
        let subscriber = fmt::Subscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set global default subscriber");
    }
}
