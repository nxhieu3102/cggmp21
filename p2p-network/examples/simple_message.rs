use p2p_network::message::InternalMessage;
use p2p_network::Message;
use p2p_network::VERSION;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("P2P Network Example");
    println!("Library version: {}", VERSION);
    
    // Create a simple message
    let payload = "Hello, P2P Network!".as_bytes().to_vec();
    let message = InternalMessage::new("greeting", Some("example-node"), payload);
    
    println!("Created message: {:?}", message);
    
    // Serialize the message
    let serialized = message.as_bytes();
    println!("Serialized message size: {} bytes", serialized.len());
    
    // Deserialize the message
    let deserialized = InternalMessage::from_bytes(&serialized)?;
    println!("Deserialized message: {:?}", deserialized);
    
    // Verify the round-trip
    assert_eq!(message.message_type, deserialized.message_type);
    assert_eq!(message.sender_id, deserialized.sender_id);
    assert_eq!(message.payload, deserialized.payload);
    assert_eq!(message.timestamp, deserialized.timestamp);
    
    println!("Message successfully round-tripped through serialization/deserialization!");
    
    Ok(())
} 
