// WebSocket Worker for handling communication between parties
let ws = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY = 3000; // 3 seconds
const MESSAGE_TIMEOUT = 10000; // 10 seconds timeout for collecting messages

// Store received messages
const receivedMessages = new Map();
let expectedMessagesCount = 3; // We expect 3 messages from other parties

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
  if (!message || !message.sender || message.round === undefined || message.data === undefined) {
    postMessage({ 
      type: 'error', 
      error: 'Invalid protocol message format', 
      message: JSON.stringify(message)
    });
    return;
  }
  
  // Process message based on round
  if (message.round === 1) {
    const senderId = message.sender;
    
    // Store unique messages from each sender
    if (!receivedMessages.has(senderId)) {
      receivedMessages.set(senderId, message);
      
      // Notify main thread about received message
      postMessage({ 
        type: 'message', 
        status: 'received', 
        sender: senderId, 
        count: receivedMessages.size 
      });
      
      // Check if we have received all expected messages
      if (receivedMessages.size >= expectedMessagesCount) {
        // Send all collected messages to main thread
        postMessage({ 
          type: 'round_complete', 
          messages: Array.from(receivedMessages.values()) 
        });
      }
    }
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
        expected: expectedMessagesCount 
      });
    }
  }, MESSAGE_TIMEOUT);
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
      setupMessageTimeout();
      break;
      
    case 'disconnect':
      if (ws) {
        ws.close();
      }
      break;
      
    default:
      postMessage({ 
        type: 'error', 
        error: 'Unknown command', 
        command: data.type 
      });
  }
}; 
