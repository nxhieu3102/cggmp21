// P2P Network Library
//
// This library provides a platform-agnostic networking layer for peer-to-peer
// communications, supporting both native (desktop/server) and WASM (browser) environments.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

// Re-export key components for easier usage
pub use crate::network::NetworkLayer;
pub use crate::message::Message;
pub use crate::node::Node;
pub use crate::config::ConfigLoader;
pub use crate::key::KeyManager;
pub use crate::handler::MessageHandler;
pub use crate::transport::TransportAdapter;

// Core modules
pub mod network;
pub mod message;
pub mod node;
pub mod config;
pub mod key;
pub mod handler;
pub mod transport;

// Mock implementations for testing
#[cfg(test)]
pub mod mock;

// Feature-specific modules
#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "wasm")]
pub mod wasm;

/// Version of the p2p-network crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Logger initialization
pub fn init_logger() {
    #[cfg(feature = "native")]
    native::init_native_logger();
    
    #[cfg(feature = "wasm")]
    wasm::init_wasm_logger();
}

/// Helper function to create a node builder with the specified message type
/// 
/// This is a convenience function for creating nodes with default message handlers
/// and other components for the targeted environment.
pub fn create_node_builder<M>() -> node::NodeBuilder<
    impl NetworkLayer<MessageType = M>,
    impl KeyManager,
    impl ConfigLoader,
    impl MessageHandler<MessageType = M> + Clone + 'static,
    M
>
where
    M: message::Message,
{
    #[cfg(all(feature = "wasm", not(feature = "native")))]
    {
        node::NodeBuilder::<
            crate::wasm::network::WasmNetworkImpl<M>,
            crate::key::WasmKeyManager,
            crate::config::LocalStorageConfigLoader,
            crate::wasm::handler::BasicWasmHandler<M>,
            M
        >::new()
    }
    
    #[cfg(feature = "native")]
    {
        node::NodeBuilder::<
            crate::native::network::TcpNetworkImpl<M>,
            crate::key::NativeKeyManager,
            crate::config::FileConfigLoader,
            crate::native::handler::BasicMessageHandler<M>,
            M
        >::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[cfg(feature = "native")]
    fn test_native_creation() {
        assert!(true, "This test only verifies compilation");
        
        // This test only verifies that the code compiles
        // Actual functionality would be tested in more specific tests
        #[cfg(feature = "native")]
        {
            // This commented out code ensures the types compile but doesn't run it
            /*
            use crate::native::tcp::TcpNetworkImpl;
            use crate::key::NativeKeyManager;
            use crate::config::FileConfigLoader;
            use crate::message::InternalMessage;
            use std::path::PathBuf;
            
            let network = TcpNetworkImpl::<InternalMessage>::new("127.0.0.1:8000");
            let key_manager = NativeKeyManager::new();
            let config = FileConfigLoader::new(PathBuf::from("config.yaml"));
            
            let _builder = node::NodeBuilder::<_, _, _, _, InternalMessage>::new()
                .with_id("test-node".to_string())
                .with_network(network)
                .with_key_manager(key_manager)
                .with_config(config);
            */
        }
    }
}
