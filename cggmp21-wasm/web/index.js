// Main JavaScript file for the WASM protocol implementation

// Configuration
const CONFIG = {
  websocketUrl: 'ws://localhost:8080',
  totalParties: 3,
  roundTimeoutMs: 15000, // 15 seconds timeout for each round
  sessionId: `session-${Date.now()}`
};

// Protocol state
let protocolState = {
  partyId: 0,
  round: 0,
  receivedMessages: [],
  keyShare: null,
  worker: null,
  roundTimerId: null,
  wasmLoaded: false,
  keygenInitialized: false
};

// UI elements
const UI = {};

// Initialize the application
async function init() {
  setupUI();
  
  // Generate a unique party ID if not provided
  if (!protocolState.partyId) {
    protocolState.partyId = Math.floor(Math.random() * 100) + 1; // Party IDs start from 1
  }
  
  // Set party ID in input field
  UI.partyIdInput.value = protocolState.partyId;
  
  updateUI('status', `Initializing as Party ${protocolState.partyId}...`);
  
  try {
    // Setup worker for WebSocket communication and WASM execution
    setupWorker();
    
    // Wait for WASM to be loaded
    setTimeout(() => {
      // Enable the start button after setup
      UI.startButton.disabled = false;
      
      updateUI('status', `Ready to start protocol. Party ID: ${protocolState.partyId}`);
    }, 1000);
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
  UI.progressFill = document.getElementById('progress-fill');
  
  // Set event listeners
  UI.startButton.addEventListener('click', startProtocol);
  UI.partyIdInput.addEventListener('change', (e) => {
    protocolState.partyId = parseInt(e.target.value.trim(), 10);
  });
  
  // Set initial values
  if (UI.partyIdInput) {
    UI.partyIdInput.value = protocolState.partyId || 1;
  }
  
  // Set initial progress
  updateProgress(0);
}

// Setup Web Worker for WebSocket communication
function setupWorker() {
  try {
    // Create a new worker
    protocolState.worker = new Worker('worker.js');
    
    // Set up message handlers for the worker
    protocolState.worker.onmessage = handleWorkerMessage;
    
    // Initialize WASM module in worker
    protocolState.worker.postMessage({
      type: 'init_wasm'
    });
    
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
  if (!protocolState.worker || !protocolState.wasmLoaded) {
    updateUI('error', 'Worker or WASM module not initialized. Please reload the page.');
    return;
  }
  
  updateUI('status', 'Starting keygen protocol...');
  UI.startButton.disabled = true;
  
  // Clear previous results and errors
  updateUI('result', '');
  updateUI('error', '');
  
  // Reset protocol state
  protocolState.round = 0;
  protocolState.receivedMessages = [];
  protocolState.keyShare = null;
  
  // Reset progress bar
  updateProgress(0);
  
  try {
    // Initialize keygen protocol in worker
    protocolState.worker.postMessage({
      type: 'init_keygen',
      partyId: protocolState.partyId,
      numParties: CONFIG.totalParties,
      sessionId: CONFIG.sessionId
    });
    
    updateUI('log', `Initialized keygen protocol with Party ID: ${protocolState.partyId}, Session: ${CONFIG.sessionId}`);
  } catch (error) {
    updateUI('error', `Error initializing keygen: ${error.message}`);
    console.error('Keygen initialization error:', error);
    resetProtocol();
  }
}

// Start round 1 of the keygen protocol
function startRound1() {
  try {
    // Run round 1 in worker
    protocolState.worker.postMessage({
      type: 'run_round_1'
    });
    
    // Update protocol state
    protocolState.round = 1;
    
    // Update progress bar (25%)
    updateProgress(25);
    
    updateUI('status', `Round 1: Generating and sending commitments... (${protocolState.round}/${4})`);
    
    // Set timeout for round 1
    setRoundTimeout(1);
  } catch (error) {
    updateUI('error', `Error in Round 1: ${error.message}`);
    console.error('Round 1 error:', error);
    resetProtocol();
  }
}

// Start round 2 of the keygen protocol
function startRound2() {
  try {
    // Run round 2 in worker
    protocolState.worker.postMessage({
      type: 'run_round_2',
      messages: protocolState.receivedMessages
    });
    
    // Update protocol state
    protocolState.round = 2;
    
    // Update progress bar (50%)
    updateProgress(50);
    
    updateUI('status', `Round 2: Processing commitments and sending decommitments... (${protocolState.round}/${4})`);
    
    // Set timeout for round 2
    setRoundTimeout(2);
  } catch (error) {
    updateUI('error', `Error in Round 2: ${error.message}`);
    console.error('Round 2 error:', error);
    resetProtocol();
  }
}

// Start round 3 of the keygen protocol
function startRound3() {
  try {
    // Run round 3 in worker
    protocolState.worker.postMessage({
      type: 'run_round_3',
      messages: protocolState.receivedMessages
    });
    
    // Update protocol state
    protocolState.round = 3;
    
    // Update progress bar (75%)
    updateProgress(75);
    
    updateUI('status', `Round 3: Generating Schnorr proofs... (${protocolState.round}/${4})`);
    
    // Set timeout for round 3
    setRoundTimeout(3);
  } catch (error) {
    updateUI('error', `Error in Round 3: ${error.message}`);
    console.error('Round 3 error:', error);
    resetProtocol();
  }
}

// Finalize the keygen protocol
function finalizeKeygen() {
  try {
    // Finalize keygen in worker
    protocolState.worker.postMessage({
      type: 'finalize_keygen',
      messages: protocolState.receivedMessages
    });
    
    // Update protocol state
    protocolState.round = 4;
    
    // Update progress bar (90%)
    updateProgress(90);
    
    updateUI('status', `Finalizing keygen: Verifying proofs and generating key share... (${protocolState.round}/${4})`);
  } catch (error) {
    updateUI('error', `Error finalizing keygen: ${error.message}`);
    console.error('Keygen finalization error:', error);
    resetProtocol();
  }
}

// Handle messages from the Web Worker
function handleWorkerMessage(event) {
  const data = event.data;
  
  switch (data.type) {
    case 'wasm_loaded':
      protocolState.wasmLoaded = true;
      updateUI('log', 'WASM module loaded successfully');
      break;
      
    case 'keygen_initialized':
      protocolState.keygenInitialized = true;
      updateUI('log', `Keygen protocol initialized for Party ${data.partyId}`);
      
      // Start round 1 after initialization
      startRound1();
      break;
      
    case 'connection':
      handleConnectionStatus(data);
      break;
      
    case 'message':
      updateUI('log', `Received message from Party ${data.sender} for Round ${data.round} (${data.count}/${CONFIG.totalParties - 1})`);
      break;
      
    case 'round_started':
      updateUI('log', `Started round ${data.round}`);
      break;
      
    case 'round_complete':
      handleRoundComplete(data);
      break;
      
    case 'keygen_complete':
      handleKeygenComplete(data);
      break;
      
    case 'error':
      handleError(data);
      break;
      
    case 'timeout':
      updateUI('error', `Timeout: Received only ${data.received} of ${data.expected} messages for Round ${data.round}`);
      break;
      
    case 'system':
      handleSystemMessage(data);
      break;
      
    case 'protocol_state':
      console.log('Protocol state:', data.state);
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
  
  updateUI('log', `Round ${data.round} complete. Received all ${protocolState.receivedMessages.length} messages.`);
  
  // Process based on current round
  if (data.round === 1) {
    // Move to Round 2
    startRound2();
  } else if (data.round === 2) {
    // Move to Round 3
    startRound3();
  } else if (data.round === 3) {
    // Finalize keygen
    finalizeKeygen();
  }
}

// Handle keygen completion
function handleKeygenComplete(data) {
  protocolState.keyShare = data.keyShare;
  
  // Update progress bar (100%)
  updateProgress(100);
  
  updateUI('status', 'Keygen protocol complete!');
  updateUI('result', `Key share generated successfully. Party ${protocolState.partyId} key share: ${truncateKeyShare(data.keyShare)}`);
  
  // Re-enable start button
  UI.startButton.disabled = false;
}

// Handle error messages
function handleError(data) {
  updateUI('error', `Error: ${data.error} - ${data.details || ''}`);
  console.error('Protocol error:', data);
  
  // Re-enable start button on error
  UI.startButton.disabled = false;
}

// Update progress bar
function updateProgress(percent) {
  if (UI.progressFill) {
    UI.progressFill.style.width = `${percent}%`;
  }
}

// Truncate key share for display
function truncateKeyShare(keyShare) {
  if (!keyShare) return '';
  
  const str = keyShare.toString();
  if (str.length <= 20) return str;
  
  return str.substring(0, 10) + '...' + str.substring(str.length - 10);
}

// Set timeout for round
function setRoundTimeout(round) {
  clearRoundTimeout();
  
  protocolState.roundTimerId = setTimeout(() => {
    updateUI('error', `Timeout in round ${round}. Please check if all parties are connected.`);
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

// Reset protocol state
function resetProtocol() {
  clearRoundTimeout();
  
  // Reset progress bar
  updateProgress(0);
  
  // Re-enable start button
  UI.startButton.disabled = false;
}

// Update UI elements
function updateUI(type, message) {
  switch (type) {
    case 'status':
      UI.statusDiv.textContent = message;
      break;
      
    case 'log':
      const logEntry = document.createElement('div');
      logEntry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
      UI.logsDiv.appendChild(logEntry);
      
      // Scroll to bottom
      UI.logsDiv.scrollTop = UI.logsDiv.scrollHeight;
      break;
      
    case 'result':
      UI.resultDiv.textContent = message;
      break;
      
    case 'error':
      UI.errorDiv.textContent = message;
      UI.errorDiv.style.display = message ? 'block' : 'none';
      break;
  }
}

// Initialize the application when the DOM is loaded
window.addEventListener('DOMContentLoaded', init); 
