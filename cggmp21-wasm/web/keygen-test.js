// Test script for CGGMP21 keygen WASM bindings

// Import the WASM module
async function testKeygen() {
  console.log("Loading WASM module...");
  
  // Import the wasm module
  const wasmModule = await import('../pkg/cggmp21_wasm.js');
  await wasmModule.default();
  
  console.log("WASM module loaded successfully", wasmModule);
  
  // Test with 3 parties
  const numParties = 3;
  const sessionId = "test-session-" + Date.now();
  const parties = [];
  
  console.log(`Testing keygen with ${numParties} parties, session ID: ${sessionId}`);
  
  // Initialize parties
  for (let i = 1; i <= numParties; i++) {
    try {
      const party = new wasmModule.KeygenProtocol(i, numParties, sessionId);
      parties.push(party);
      console.log(`Party ${i} initialized successfully`);
    } catch (error) {
      console.error(`Failed to initialize party ${i}:`, error);
      return;
    }
  }
  
  // Run round 1 for all parties
  const round1Messages = [];
  for (let i = 0; i < numParties; i++) {
    try {
      const outgoingMsg = parties[i].run_round_1();
      round1Messages.push(outgoingMsg);
      console.log(`Party ${i+1} completed round 1`);
    } catch (error) {
      console.error(`Error in round 1 for party ${i+1}:`, error);
      return;
    }
  }
  
  // Create incoming message arrays for round 2
  const round2IncomingMessages = [];
  for (let i = 0; i < numParties; i++) {
    // Each party receives messages from all other parties
    const partyIncomingMsgs = [];
    for (let j = 0; j < numParties; j++) {
      if (i !== j) {
        // Parse the outgoing message
        const outMsg = round1Messages[j];
        partyIncomingMsgs.push(outMsg);
      }
    }
    
    // Store the incoming messages for this party
    round2IncomingMessages.push(partyIncomingMsgs);
  }
  
  // Run round 2 for all parties
  const round2Messages = [];
  for (let i = 0; i < numParties; i++) {
    try {
      // Convert array to JsValue
      const incomingMsgsJs = wasmModule.serialize_messages(round2IncomingMessages[i]);
      
      // Run round 2
      const outgoingMsg = parties[i].run_round_2(incomingMsgsJs);
      round2Messages.push(outgoingMsg);
      console.log(`Party ${i+1} completed round 2`);
    } catch (error) {
      console.error(`Error in round 2 for party ${i+1}:`, error);
      return;
    }
  }
  
  // Create incoming message arrays for round 3
  const round3IncomingMessages = [];
  for (let i = 0; i < numParties; i++) {
    // Each party receives messages from all other parties
    const partyIncomingMsgs = [];
    for (let j = 0; j < numParties; j++) {
      if (i !== j) {
        // Parse the outgoing message
        const outMsg = round2Messages[j];
        
        partyIncomingMsgs.push(outMsg);
      }
    }
    
    // Store the incoming messages for this party
    round3IncomingMessages.push(partyIncomingMsgs);
  }
  
  // Run round 3 for all parties
  const round3Messages = [];
  for (let i = 0; i < numParties; i++) {
    try {
      // Convert array to JsValue
      const incomingMsgsJs = wasmModule.serialize_messages(round3IncomingMessages[i]);
      
      // Run round 3
      const outgoingMsg = parties[i].run_round_3(incomingMsgsJs);
      round3Messages.push(outgoingMsg);
      console.log(`Party ${i+1} completed round 3`);
    } catch (error) {
      console.error(`Error in round 3 for party ${i+1}:`, error);
      return;
    }
  }
  
  // Create incoming message arrays for finalization
  const finalIncomingMessages = [];
  for (let i = 0; i < numParties; i++) {
    // Each party receives messages from all other parties
    const partyIncomingMsgs = [];
    for (let j = 0; j < numParties; j++) {
      if (i !== j) {
        // Parse the outgoing message
        const outMsg = round3Messages[j];        
        partyIncomingMsgs.push(outMsg);
      }
    }
    
    // Store the incoming messages for this party
    finalIncomingMessages.push(partyIncomingMsgs);
  }
  
  // Finalize keygen for all parties
  const keyShares = [];
  for (let i = 0; i < numParties; i++) {
    try {
      // Convert array to JsValue
      const incomingMsgsJs = wasmModule.serialize_messages(finalIncomingMessages[i]);
      
      // Finalize
      const keyShare = parties[i].finalize(incomingMsgsJs);
      keyShares.push(keyShare);
      console.log(`Party ${i+1} finalized keygen with key share:`, keyShare);
    } catch (error) {
      console.error(`Error in finalization for party ${i+1}:`, error);
      return;
    }
  }
  
  // Check if all parties have completed the protocol
  for (let i = 0; i < numParties; i++) {
    const isComplete = parties[i].is_complete();
    console.log(`Party ${i+1} completion status:`, isComplete);
  }
  
  console.log("Keygen test completed successfully!");
  return keyShares;
}

// Run the test when the page loads
window.onload = async function() {
  try {
    const keyShares = await testKeygen();
    
    // Display results on the page
    const resultElement = document.getElementById('result');
    if (resultElement) {
      resultElement.textContent = `Keygen completed successfully with ${keyShares.length} key shares.`;
    }
  } catch (error) {
    console.error("Test failed:", error);
    
    // Display error on the page
    const resultElement = document.getElementById('result');
    if (resultElement) {
      resultElement.textContent = `Keygen test failed: ${error}`;
      resultElement.style.color = 'red';
    }
  }
}; 
