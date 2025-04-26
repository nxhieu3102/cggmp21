// Example of using cggmp21-keygen in JavaScript
async function initKeygen() {
  try {
    // Import the wasm module
    const { 
      default: init, 
      KeygenConfig, 
      is_wasm_loaded, 
      get_version, 
      create_execution_id,
      serialize_message,
      deserialize_message,
      start_threshold_keygen,
      ThresholdKeygenSession
    } = await import('./pkg/crates_compile_in_nostd_wasm.js');
    
    // Initialize the WASM module
    await init();
    
    console.log("WASM loaded:", is_wasm_loaded());
    console.log("Version:", get_version());
    
    // Create a keygen configuration
    const partyIndex = 1;  // Your party index (1-based)
    const numParties = 3;  // Total number of parties
    
    // For non-threshold key generation
    const config = new KeygenConfig(partyIndex, numParties);
    console.log("Created non-threshold config");
    
    // For threshold key generation (e.g., 2-of-3)
    const thresholdConfig = new KeygenConfig(partyIndex, numParties).with_threshold(2);
    console.log("Created threshold config with t=2");
    
    // Create a unique execution ID for this keygen session
    const sessionId = "session-" + Date.now();
    const executionId = create_execution_id(sessionId);
    console.log("Execution ID:", executionId);
    
    // Example of message serialization/deserialization
    // This is used for passing protocol messages between participants
    const exampleMessage = new Uint8Array([1, 2, 3, 4, 5]);
    const serialized = serialize_message(exampleMessage);
    console.log("Serialized message:", serialized);
    
    const deserialized = deserialize_message(serialized);
    console.log("Deserialized message:", deserialized);
    
    console.log("\n--- Testing Threshold Keygen ---");
    
    // Create a threshold keygen session
    const session = start_threshold_keygen(partyIndex, numParties, 2, sessionId);
    console.log("Created threshold keygen session");
    
    // Generate Round 1 message
    const round1Message = session.generate_round1_message();
    console.log("Generated Round 1 message:", round1Message);
    
    // Simulate processing messages from other parties
    const otherPartyMessages = {
      "party2": "SIMULATED_MESSAGE_FROM_PARTY_2",
      "party3": "SIMULATED_MESSAGE_FROM_PARTY_3"
    };
    
    try {
      const result = session.process_round1_messages(otherPartyMessages);
      console.log("Processed Round 1 messages:", result);
    } catch (error) {
      console.error("Error processing messages:", error);
    }
    
    console.log("\n--- Threshold Keygen Simulation ---");
    console.log(`Party ${partyIndex} would now continue with the full protocol:`);
    console.log("1. Generate and exchange round 1 messages with all parties");
    console.log("2. Generate and exchange round 2 messages with all parties");
    console.log("3. Generate and exchange round 3 messages with all parties");
    console.log("4. Verify all proofs and compute the key share");
    
    // In a real application, you would:
    // 1. Setup communication channels between parties
    // 2. Generate protocol messages
    // 3. Exchange messages with other parties
    // 4. Process incoming messages
    // 5. Complete the protocol to get key shares
    
  } catch (error) {
    console.error("Error:", error);
  }
}

// Call the function when the script loads
initKeygen().catch(console.error); 
