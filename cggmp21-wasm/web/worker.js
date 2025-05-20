// WebSocket Worker for handling communication between parties
let ws = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY = 3000; // 3 seconds
const MESSAGE_TIMEOUT = 10000; // 10 seconds timeout for collecting messages

// Store received messages
const receivedMessages = new Map();
let expectedMessagesCount = 3; // We expect 3 messages from other parties

// WASM module
let wasmModule = null;
let keygenProtocol = null;

// Protocol configuration
let protocolConfig = {
  partyId: 0,
  numParties: 0,
  sessionId: '',
  currentRound: 0,
  maxRounds: 4 // Keygen has 4 rounds (including finalization)
};

// Connect to WebSocket server
function connectToServer(serverUrl) {
  try {
    ws = new WebSocket(serverUrl);
    
    ws.onopen = () => {
      postMessage({ type: 'connection', status: 'connected' });
      reconnectAttempts = 0;
    };
    
    ws.onclose = () => {
      postMessage({ type: 'connection', status: 'disconnected' });
      attemptReconnect(serverUrl);
    };
    
    ws.onerror = (error) => {
      postMessage({ 
        type: 'error', 
        error: 'WebSocket error', 
        details: error.message || 'Unknown error'
      });
      
      if (ws.readyState !== WebSocket.OPEN) {
        attemptReconnect(serverUrl);
      }
    };
    
    ws.onmessage = (event) => {
      try {
        // Handle different data types (text, blob, arraybuffer)
        if (typeof event.data === 'string') {
          // Data is already a string, parse directly
          const message = JSON.parse(event.data);
          handleMessage(message);
        } else if (event.data instanceof Blob) {
          // Convert Blob to text and then parse
          const reader = new FileReader();
          reader.onload = () => {
            try {
              const message = JSON.parse(reader.result);
              handleMessage(message);
            } catch (error) {
              postMessage({ 
                type: 'error', 
                error: 'Invalid message format', 
                details: error.message,
                data: reader.result
              });
            }
          };
          reader.onerror = (error) => {
            postMessage({ 
              type: 'error', 
              error: 'Failed to read Blob data', 
              details: error.message 
            });
          };
          reader.readAsText(event.data);
        } else if (event.data instanceof ArrayBuffer) {
          // Convert ArrayBuffer to text and then parse
          const text = new TextDecoder().decode(event.data);
          const message = JSON.parse(text);
          handleMessage(message);
        } else {
          throw new Error('Unsupported message format');
        }
      } catch (error) {
        postMessage({ 
          type: 'error', 
          error: 'Invalid message format', 
          details: error.message, 
          data: typeof event.data
        });
      }
    };
  } catch (error) {
    postMessage({ 
      type: 'error', 
      error: 'Connection error', 
      details: error.message 
    });
    attemptReconnect(serverUrl);
  }
}

// Attempt to reconnect to the server
function attemptReconnect(serverUrl) {
  if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
    reconnectAttempts++;
    
    setTimeout(() => {
      postMessage({ 
        type: 'connection', 
        status: 'reconnecting', 
        attempt: reconnectAttempts 
      });
      connectToServer(serverUrl);
    }, RECONNECT_DELAY);
  } else {
    postMessage({ 
      type: 'connection', 
      status: 'failed', 
      error: 'Max reconnection attempts reached' 
    });
  }
}

// Handle incoming messages
function handleMessage(message) {
  // Handle system messages from the server
  if (message.type === 'system') {
    postMessage({ 
      type: 'system', 
      event: message.event,
      message: message.message || '',
      sender: message.sender
    });
    return;
  }
  
  // Validate protocol message format
  if (!message || !message.sender || message.round === undefined) {
    postMessage({ 
      type: 'error', 
      error: 'Invalid protocol message format', 
      message: JSON.stringify(message)
    });
    return;
  }
  
  // Check if this message is for the current round
  if (message.round === protocolConfig.currentRound) {
    const senderId = message.sender;
    
    // Store unique messages from each sender
    if (!receivedMessages.has(senderId)) {
      receivedMessages.set(senderId, message);
      
      // Notify main thread about received message
      postMessage({ 
        type: 'message', 
        status: 'received', 
        sender: senderId, 
        count: receivedMessages.size,
        round: message.round
      });
      
      // Check if we have received all expected messages
      if (receivedMessages.size >= expectedMessagesCount) {
        // Send all collected messages to main thread
        postMessage({ 
          type: 'round_complete', 
          messages: Array.from(receivedMessages.values()),
          round: message.round
        });
        
        // Clear received messages for next round
        receivedMessages.clear();
      }
    }
  } else {
    postMessage({
      type: 'error',
      error: 'Unexpected round',
      details: `Expected round ${protocolConfig.currentRound}, got round ${message.round}`
    });
  }
}

// Send a message to all other parties
function sendMessage(message) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      const messageString = JSON.stringify(message);
      ws.send(messageString);
      return true;
    } catch (error) {
      postMessage({ 
        type: 'error', 
        error: 'Failed to send message', 
        details: error.message
      });
      return false;
    }
  } else {
    postMessage({ 
      type: 'error', 
      error: 'WebSocket not connected', 
      action: 'send' 
    });
    return false;
  }
}

// Setup message timeout
function setupMessageTimeout() {
  setTimeout(() => {
    if (receivedMessages.size < expectedMessagesCount) {
      postMessage({ 
        type: 'timeout', 
        received: receivedMessages.size, 
        expected: expectedMessagesCount,
        round: protocolConfig.currentRound
      });
    }
  }, MESSAGE_TIMEOUT);
}

// Initialize WASM module
async function initWasmModule() {
  try {
    // Import the wasm module
    wasmModule = await import('../pkg/cggmp21_wasm.js');
    await wasmModule.default();
    console.log('WASM module loaded');
    try {
      const msg = wasmModule.create_message_round_1({
        i: 1,
        t: 2,
        n: 3,
        sid: '1234567890'
      });
      console.log('create_message_round_1 function exists', msg);
    } catch (error) {
      console.error('error', error);
    }
    postMessage({ type: 'wasm_loaded', status: 'success' });
    
    return true;
  } catch (error) {
    postMessage({ 
      type: 'error', 
      error: 'Failed to load WASM module', 
      details: error.message
    });
    
    return false;
  }
}

// Initialize keygen protocol
function initKeygenProtocol(partyId, numParties, sessionId) {
  try {
    if (!wasmModule) {
      throw new Error('WASM module not loaded');
    }
    
    keygenProtocol = new wasmModule.KeygenProtocol(partyId, numParties, sessionId);
    
    // Store configuration
    protocolConfig = {
      partyId,
      numParties,
      sessionId,
      currentRound: 0,
      maxRounds: 4
    };
    
    // We expect numParties - 1 messages from other parties
    expectedMessagesCount = numParties - 1;
    
    postMessage({ 
      type: 'keygen_initialized', 
      partyId,
      numParties,
      sessionId
    });
    
    return true;
  } catch (error) {
    postMessage({ 
      type: 'error', 
      error: 'Failed to initialize keygen protocol', 
      details: error.message 
    });
    
    return false;
  }
}

// Run round 1 of keygen protocol
function runRound1() {
  try {
    if (!keygenProtocol) {
      throw new Error('Keygen protocol not initialized');
    }
    
    // Run round 1
    const outgoingMsg = keygenProtocol.run_round_1();
    
    // Update current round
    protocolConfig.currentRound = 1;
    
    // Setup timeout for receiving messages
    setupMessageTimeout();
    
    // Send message to other parties
    sendMessage(outgoingMsg);
    
    // Notify main thread
    postMessage({ 
      type: 'round_started', 
      round: 1
    });
    
    return true;
  } catch (error) {
    postMessage({ 
      type: 'error', 
      error: 'Failed to run round 1', 
      details: error.message 
    });
    
    return false;
  }
}

// Run round 2 of keygen protocol
function runRound2(incomingMessages) {
  try {
    if (!keygenProtocol) {
      throw new Error('Keygen protocol not initialized');
    }
    
    // Serialize incoming messages
    const incomingMsgsJs = wasmModule.serialize_messages(incomingMessages);
    
    // Run round 2
    const outgoingMsg = keygenProtocol.run_round_2(incomingMsgsJs);
    
    // Update current round
    protocolConfig.currentRound = 2;
    
    // Setup timeout for receiving messages
    setupMessageTimeout();
    
    // Send message to other parties
    sendMessage(outgoingMsg);
    
    // Notify main thread
    postMessage({ 
      type: 'round_started', 
      round: 2
    });
    
    return true;
  } catch (error) {
    postMessage({ 
      type: 'error', 
      error: 'Failed to run round 2', 
      details: error.message 
    });
    
    return false;
  }
}

// Run round 3 of keygen protocol
function runRound3(incomingMessages) {
  try {
    if (!keygenProtocol) {
      throw new Error('Keygen protocol not initialized');
    }
    
    // Serialize incoming messages
    const incomingMsgsJs = wasmModule.serialize_messages(incomingMessages);
    
    // Run round 3
    const outgoingMsg = keygenProtocol.run_round_3(incomingMsgsJs);
    
    // Update current round
    protocolConfig.currentRound = 3;
    
    // Setup timeout for receiving messages
    setupMessageTimeout();
    
    // Send message to other parties
    sendMessage(outgoingMsg);
    
    // Notify main thread
    postMessage({ 
      type: 'round_started', 
      round: 3
    });
    
    return true;
  } catch (error) {
    postMessage({ 
      type: 'error', 
      error: 'Failed to run round 3', 
      details: error.message 
    });
    
    return false;
  }
}

// Finalize keygen protocol
function finalizeKeygen(incomingMessages) {
  try {
    if (!keygenProtocol) {
      throw new Error('Keygen protocol not initialized');
    }
    
    // Serialize incoming messages
    const incomingMsgsJs = wasmModule.serialize_messages(incomingMessages);
    
    // Finalize keygen
    const keyShare = keygenProtocol.finalize(incomingMsgsJs);
    
    // Update current round
    protocolConfig.currentRound = 4;
    
    // Check if protocol is complete
    const isComplete = keygenProtocol.is_complete();
    
    // Notify main thread
    postMessage({ 
      type: 'keygen_complete', 
      keyShare,
      isComplete
    });
    
    return true;
  } catch (error) {
    postMessage({ 
      type: 'error', 
      error: 'Failed to finalize keygen', 
      details: error.message 
    });
    
    return false;
  }
}

// Get current protocol state
function getProtocolState() {
  try {
    if (!keygenProtocol) {
      throw new Error('Keygen protocol not initialized');
    }
    
    const stateJson = keygenProtocol.get_state();
    
    return stateJson;
  } catch (error) {
    postMessage({ 
      type: 'error', 
      error: 'Failed to get protocol state', 
      details: error.message 
    });
    
    return null;
  }
}

// Handle messages from the main thread
self.onmessage = async (event) => {
  const data = event.data;
  
  switch (data.type) {
    case 'connect':
      connectToServer(data.serverUrl);
      break;
      
    case 'send':
      sendMessage(data.message);
      break;
      
    case 'set_party_count':
      // Set the number of expected messages (total parties - 1)
      expectedMessagesCount = data.count - 1;
      break;
      
    case 'disconnect':
      if (ws) {
        ws.close();
      }
      break;
      
    case 'init_wasm':
      await initWasmModule();
      break;
      
    case 'init_keygen':
      initKeygenProtocol(data.partyId, data.numParties, data.sessionId);
      break;
      
    case 'run_round_1':
      runRound1();
      break;
      
    case 'run_round_2':
      runRound2(data.messages);
      break;
      
    case 'run_round_3':
      runRound3(data.messages);
      break;
      
    case 'finalize_keygen':
      finalizeKeygen(data.messages);
      break;
      
    case 'get_state':
      const stateJson = getProtocolState();
      postMessage({
        type: 'protocol_state',
        state: stateJson
      });
      break;
      
    default:
      postMessage({ 
        type: 'error', 
        error: 'Unknown command', 
        command: data.type 
      });
  }
}; 
