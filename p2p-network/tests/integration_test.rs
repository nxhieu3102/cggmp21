// Basic integration test for p2p-network crate
//
// This test verifies that the crate can be used correctly from an external context

use p2p_network::message::InternalMessage;
use p2p_network::VERSION;

#[test]
fn test_create_message() {
    // Create a simple message
    let payload = vec![1, 2, 3, 4];
    let message = InternalMessage::new("test", Some("sender-1"), payload.clone());
    
    // Verify the message properties
    assert_eq!(message.message_type, "test");
    assert_eq!(message.sender_id, Some("sender-1".to_string()));
    assert_eq!(message.payload, payload);
    assert!(message.timestamp > 0);
}

#[test]
fn test_version() {
    // Verify that the version constant is accessible
    assert!(!VERSION.is_empty());
    println!("P2P Network version: {}", VERSION);
} 
