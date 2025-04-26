// Main JavaScript file for the WASM protocol implementation

// Configuration
const CONFIG = {
  websocketUrl: 'ws://localhost:8080',
  totalParties: 4,
  roundTimeoutMs: 15000 // 15 seconds timeout for each round
};

// Protocol state
let protocolState = {
  partyId: '',
  round: 0,
  protocolInstance: null,
  ownNumber: null,
  receivedMessages: [],
  result: null,
  worker: null,
  roundTimerId: null
};

// UI elements
const UI = {};

// Initialize the application
async function init() {
  setupUI();
  
  // Generate a unique party ID if not provided
  if (!protocolState.partyId) {
    protocolState.partyId = `party${Math.floor(Math.random() * 10000)}`;
  }
  
  updateUI('status', `Initializing as ${protocolState.partyId}...`);
  
  try {
    // Load the WASM module
    const wasmModule = await import('./pkg/cggmp21_wasm.js');
    await wasmModule.default();
    
    // Initialize protocol with party ID
    protocolState.protocolInstance = new wasmModule.Protocol(protocolState.partyId);
    
    updateUI('status', `WASM module loaded. Party ID: ${protocolState.partyId}`);
    
    // Setup worker for WebSocket communication
    setupWorker();
    
    // Enable the start button
    UI.startButton.disabled = false;
  } catch (error) {
    updateUI('error', `Failed to initialize: ${error.message}`);
    console.error('Initialization error:', error);
  }
}

// Setup UI elements
function setupUI() {
  // Get UI elements
  UI.partyIdInput = document.getElementById('party-id');
  UI.startButton = document.getElementById('start-protocol');
  UI.statusDiv = document.getElementById('status');
  UI.logsDiv = document.getElementById('logs');
  UI.resultDiv = document.getElementById('result');
  UI.errorDiv = document.getElementById('error');
  
  // Set event listeners
  UI.startButton.addEventListener('click', startProtocol);
  UI.partyIdInput.addEventListener('change', (e) => {
    protocolState.partyId = e.target.value.trim();
  });
  
  // Set initial values
  if (UI.partyIdInput) {
    UI.partyIdInput.value = `party${Math.floor(Math.random() * 10000)}`;
    protocolState.partyId = UI.partyIdInput.value;
  }
}

// Setup Web Worker for WebSocket communication
function setupWorker() {
  try {
    // Create a new worker
    protocolState.worker = new Worker('worker.js');
    
    // Set up message handlers for the worker
    protocolState.worker.onmessage = handleWorkerMessage;
    
    // Connect to the WebSocket server
    protocolState.worker.postMessage({
      type: 'connect',
      serverUrl: CONFIG.websocketUrl
    });
    
    // Set the number of parties
    protocolState.worker.postMessage({
      type: 'set_party_count',
      count: CONFIG.totalParties
    });
    
    updateUI('log', 'Web Worker initialized for WebSocket communication');
  } catch (error) {
    updateUI('error', `Failed to initialize worker: ${error.message}`);
    console.error('Worker initialization error:', error);
  }
}

// Start the protocol execution
function startProtocol() {
  if (!protocolState.protocolInstance) {
    updateUI('error', 'Protocol not initialized. Please reload the page.');
    return;
  }
  
  updateUI('status', 'Starting protocol...');
  UI.startButton.disabled = true;
  
  // Clear previous results and errors
  updateUI('result', '');
  updateUI('error', '');
  
  // Reset protocol state
  protocolState.round = 1;
  protocolState.receivedMessages = [];
  
  // Start Round 1
  try {
    // Generate random number and create message
    const messageObj = protocolState.protocolInstance.run_round_1();
    
    // Get the random number for display
    protocolState.ownNumber = messageObj.data;
    
    updateUI('log', `Round 1: Generated random number ${protocolState.ownNumber}`);
    
    // Send message to other parties via the worker
    protocolState.worker.postMessage({
      type: 'send',
      message: messageObj
    });
    
    updateUI('status', `Round 1: Sent number ${protocolState.ownNumber}. Waiting for other parties...`);
    
    // Set timeout for round 1
    setRoundTimeout(100);
  } catch (error) {
    updateUI('error', `Error in Round 1: ${error.message}`);
    console.error('Round 1 error:', error);
    resetProtocol();
  }
}

// Handle messages from the Web Worker
function handleWorkerMessage(event) {
  const data = event.data;
  
  switch (data.type) {
    case 'connection':
      handleConnectionStatus(data);
      break;
      
    case 'message':
      updateUI('log', `Received message from ${data.sender} (${data.count}/${CONFIG.totalParties - 1})`);
      break;
      
    case 'round_complete':
      handleRoundComplete(data);
      break;
      
    case 'error':
      updateUI('error', `Worker error: ${data.error} - ${data.details || ''}`);
      console.error('Worker error:', data);
      break;
      
    case 'timeout':
      updateUI('error', `Timeout: Received only ${data.received} of ${data.expected} messages`);
      break;
      
    case 'system':
      handleSystemMessage(data);
      break;
      
    default:
      console.log('Unknown message from worker:', data);
  }
}

// Handle system messages from the server
function handleSystemMessage(data) {
  if (data.event === 'welcome') {
    updateUI('log', `Server message: ${data.message}`);
  } else if (data.event === 'disconnect') {
    updateUI('log', `Party disconnected: ${data.sender}`);
  }
}

// Handle connection status updates
function handleConnectionStatus(data) {
  switch (data.status) {
    case 'connected':
      updateUI('status', 'Connected to WebSocket server');
      break;
      
    case 'disconnected':
      updateUI('status', 'Disconnected from WebSocket server');
      break;
      
    case 'reconnecting':
      updateUI('status', `Reconnecting to server (attempt ${data.attempt})...`);
      break;
      
    case 'failed':
      updateUI('error', `Connection failed: ${data.error}`);
      break;
  }
}

// Handle round completion
function handleRoundComplete(data) {
  // Clear the round timeout
  clearRoundTimeout();
  
  // Store received messages
  protocolState.receivedMessages = data.messages;
  
  updateUI('log', `Round ${protocolState.round} complete. Received all ${protocolState.receivedMessages.length} messages.`);
  
  // Process based on current round
  if (protocolState.round === 1) {
    // Move to Round 2
    proceedToRound2();
  }
}

// Proceed to Round 2
function proceedToRound2() {
  protocolState.round = 2;
  
  try {
    // Calculate sum using Rust WASM
    const result = protocolState.protocolInstance.run_round_2(protocolState.receivedMessages);
    protocolState.result = result;
    
    updateUI('status', 'Protocol complete!');
    updateUI('result', `Final result: Sum of all numbers = ${result}`);
    
    // Show breakdown of numbers
    let breakdown = `Own number: ${protocolState.ownNumber}\n`;
    protocolState.receivedMessages.forEach(msg => {
      breakdown += `${msg.sender}: ${msg.data}\n`;
    });
    
    updateUI('log', `Number breakdown:\n${breakdown}`);
    
    // Reset to allow another run
    UI.startButton.disabled = false;
  } catch (error) {
    updateUI('error', `Error in Round 2: ${error.message}`);
    console.error('Round 2 error:', error);
    resetProtocol();
  }
}

// Set timeout for a round
function setRoundTimeout(round) {
  // Clear any existing timer
  clearRoundTimeout();
  
  // Set new timer
  protocolState.roundTimerId = setTimeout(() => {
    updateUI('error', `Timeout in Round ${round}: Not all messages were received within ${CONFIG.roundTimeoutMs / 1000} seconds`);
    resetProtocol();
  }, CONFIG.roundTimeoutMs);
}

// Clear round timeout
function clearRoundTimeout() {
  if (protocolState.roundTimerId) {
    clearTimeout(protocolState.roundTimerId);
    protocolState.roundTimerId = null;
  }
}

// Reset protocol state to allow another run
function resetProtocol() {
  protocolState.round = 0;
  UI.startButton.disabled = false;
  clearRoundTimeout();
}

// Update UI elements
function updateUI(type, message) {
  switch (type) {
    case 'status':
      if (UI.statusDiv) UI.statusDiv.textContent = message;
      console.log('Status:', message);
      break;
      
    case 'log':
      if (UI.logsDiv) {
        const logEntry = document.createElement('div');
        logEntry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        UI.logsDiv.appendChild(logEntry);
        UI.logsDiv.scrollTop = UI.logsDiv.scrollHeight;
      }
      console.log('Log:', message);
      break;
      
    case 'result':
      if (UI.resultDiv) UI.resultDiv.textContent = message;
      if (message) console.log('Result:', message);
      break;
      
    case 'error':
      if (UI.errorDiv) {
        UI.errorDiv.textContent = message;
        UI.errorDiv.style.display = message ? 'block' : 'none';
      }
      if (message) console.error('Error:', message);
      break;
  }
}

// Initialize when the page loads
window.addEventListener('DOMContentLoaded', init); 
