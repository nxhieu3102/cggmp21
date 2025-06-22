import init, {
    StatefulKeygenProtocol,
    StatefulAuxGenProtocol,
    StatefulSigningProtocol
} from '../pkg/cggmp21_wasm.js';

// Configuration for the demo
const CONFIG = {
    websocketUrl: 'ws://localhost:8080',
    totalParties: 3,
    threshold: 2,
    roundTimeoutMs: 30000, // 30 seconds timeout
    reconnectDelay: 3000,
    maxReconnectAttempts: 5
};

// Global demo state
class DemoState {
    constructor() {
        this.partyId = 0;
        this.currentPhase = 'waiting'; // waiting, keygen, auxgen, signing, completed
        this.currentRound = 0;
        this.sessionId = `demo-1`;
        this.websocket = null;
        this.worker = null;
        this.wasmInitialized = false;
        this.connectedParties = new Set();
        this.roundData = new Map();
        this.keyShares = null;
        this.reconnectAttempts = 0;
        this.isReconnecting = false;
    }

    reset() {
        this.currentPhase = 'waiting';
        this.currentRound = 0;
        this.roundData.clear();
        this.keyShares = null;
        this.connectedParties.clear();
    }
}

// Initialize demo state
const demoState = new DemoState();

// DOM elements
const UI = {
    // Connection
    connectionStatus: document.getElementById('connectionStatus'),
    connectBtn: document.getElementById('connectBtn'),

    // Party config
    partyIdInput: document.getElementById('partyId'),
    messageToSignInput: document.getElementById('messageToSign'),

    // Control buttons
    startProtocolBtn: document.getElementById('startProtocolBtn'),
    runKeygenBtn: document.getElementById('runKeygenBtn'),
    runSigningBtn: document.getElementById('runSigningBtn'),
    resetBtn: document.getElementById('resetBtn'),
    checkReadinessBtn: document.getElementById('checkReadinessBtn'),

    // Progress
    progressFill: document.getElementById('progressFill'),
    progressText: document.getElementById('progressText'),

    // Logs and results
    logSection: document.getElementById('logSection'),
    resultsSection: document.getElementById('resultsSection'),
    resultsContent: document.getElementById('resultsContent'),

    // Phase indicators
    keygenPhase: document.getElementById('keygenPhase'),
    auxgenPhase: document.getElementById('auxgenPhase'),
    signingPhase: document.getElementById('signingPhase'),

    // Party cards
    partyCards: {
        0: document.getElementById('party0'),
        1: document.getElementById('party1'),
        2: document.getElementById('party2')
    }
};

// Logging utility with different types
function log(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${type}`;
    logEntry.textContent = `[${timestamp}] ${message}`;

    UI.logSection.appendChild(logEntry);
    UI.logSection.scrollTop = UI.logSection.scrollHeight;

    console.log(`[${type.toUpperCase()}] ${message}`);
}

// Update progress bar
function updateProgress(percentage, text) {
    UI.progressFill.style.width = `${percentage}%`;
    UI.progressFill.textContent = `${percentage}%`;
    UI.progressText.textContent = text;
}

// Update phase indicators
function updatePhaseIndicator(phase, status) {
    const phaseMap = {
        'keygen': UI.keygenPhase,
        'auxgen': UI.auxgenPhase,
        'signing': UI.signingPhase
    };

    const element = phaseMap[phase];
    if (!element) return;

    const icon = element.querySelector('.phase-icon');

    // Reset classes
    element.classList.remove('active', 'completed');
    icon.classList.remove('pending', 'active', 'completed');

    // Set new status
    if (status === 'active') {
        element.classList.add('active');
        icon.classList.add('active');
    } else if (status === 'completed') {
        element.classList.add('completed');
        icon.classList.add('completed');
    } else {
        icon.classList.add('pending');
    }
}

// Update party status in UI
function updatePartyStatus(partyId, status, message = '') {
    const card = UI.partyCards[partyId];
    if (!card) return;

    const statusIndicator = card.querySelector('.party-status');
    const messageDiv = card.querySelector('div:last-child');

    // Reset classes
    card.classList.remove('connected', 'active');
    statusIndicator.classList.remove('offline', 'online', 'active');

    // Set new status
    if (status === 'online') {
        card.classList.add('connected');
        statusIndicator.classList.add('online');
    } else if (status === 'active') {
        card.classList.add('active');
        statusIndicator.classList.add('active');
    } else {
        statusIndicator.classList.add('offline');
    }

    messageDiv.textContent = message || (status === 'online' ? 'Connected' : 'Waiting...');
}

// Update connection status
function updateConnectionStatus(connected, message = '') {
    const statusElement = UI.connectionStatus;
    const statusIndicator = statusElement.querySelector('.party-status');
    const statusText = statusElement.querySelector('span:last-child');

    statusElement.classList.remove('connected', 'disconnected');
    statusIndicator.classList.remove('offline', 'online');

    if (connected) {
        statusElement.classList.add('connected');
        statusIndicator.classList.add('online');
        statusText.textContent = message || 'Connected to server';
    } else {
        statusElement.classList.add('disconnected');
        statusIndicator.classList.add('offline');
        statusText.textContent = message || 'Disconnected from server';
    }
}

// Initialize WASM module
async function initializeWasm() {
    if (!demoState.wasmInitialized) {
        try {
            await init();
            demoState.wasmInitialized = true;
            log('WASM module initialized successfully', 'success');
            return true;
        } catch (error) {
            log(`Failed to initialize WASM: ${error.message}`, 'error');
            return false;
        }
    }
    return true;
}

// Initialize Web Worker for cryptographic operations
function initializeWorker() {
    if (demoState.worker) {
        demoState.worker.terminate();
    }

    demoState.worker = new Worker('./protocol-worker.js', { type: 'module' });

    demoState.worker.onmessage = (event) => {
        const { type, data } = event.data;

        switch (type) {
            case 'log':
                log(data.message, data.level);
                break;

            case 'progress':
                updateProgress(data.percentage, data.message);
                break;

            case 'phase_complete':
                handlePhaseComplete(data);
                break;

            case 'round_message':
                sendRoundMessage(data);
                break;

            case 'error':
                log(`Worker error: ${data.message}`, 'error');
                break;

            case 'ready':
                log('Protocol worker ready', 'success');
                break;
        }
    };

    demoState.worker.onerror = (error) => {
        log(`Worker error: ${error.message}`, 'error');
    };
}

// WebSocket connection management
function connectToServer() {
    if (demoState.websocket) {
        demoState.websocket.close();
    }

    demoState.websocket = new WebSocket(CONFIG.websocketUrl);

    demoState.websocket.onopen = () => {
        // Send identification message
        sendMessage({
            type: 'identification',
            partyId: demoState.partyId,
            sessionId: demoState.sessionId
        });
    };

    demoState.websocket.onclose = () => {
        log('Disconnected from server', 'warning');
        updateConnectionStatus(false);

        UI.connectBtn.textContent = '🔗 Connect to Server';
        UI.connectBtn.disabled = false;
        UI.startProtocolBtn.disabled = true;
        UI.runKeygenBtn.disabled = true;
        UI.checkReadinessBtn.disabled = true;

        // Auto-reconnect logic
        if (!demoState.isReconnecting && demoState.reconnectAttempts < CONFIG.maxReconnectAttempts) {
            demoState.isReconnecting = true;
            demoState.reconnectAttempts++;

            setTimeout(() => {
                log(`Attempting to reconnect... (${demoState.reconnectAttempts}/${CONFIG.maxReconnectAttempts})`, 'info');
                connectToServer();
            }, CONFIG.reconnectDelay);
        }
    };

    demoState.websocket.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            handleWebSocketMessage(message);
        } catch (error) {
            log(`Error parsing message: ${error.message}`, 'error');
        }
    };

    demoState.websocket.onerror = (error) => {
        log(`WebSocket error: ${error.message || 'Connection failed'}`, 'error');
    };
}

// Handle incoming WebSocket messages
function handleWebSocketMessage(message) {
    switch (message.type) {
        case 'system':
            handleSystemMessage(message);
            break;

        case 'party_joined':
            handlePartyJoined(message);
            break;

        case 'party_left':
            handlePartyLeft(message);
            break;

        case 'protocol_message':
            handleProtocolMessage(message);
            break;

        case 'phase_sync':
            handlePhaseSync(message);
            break;

        case 'ready_status':
            handleReadyStatus(message);
            break;

        default:
            log(`Unknown message type: ${message.type}`, 'warning');
    }
}

// Handle system messages
function handleSystemMessage(message) {
    console.log('handleSystemMessage', message);
    if (message.event === 'welcome') {
        log(message.message, 'info');
    } else if (message.event === 'disconnect') {
        log(`Party ${message.sender} disconnected`, 'warning');
        demoState.connectedParties.delete(message.sender);
        updatePartyStatus(message.sender, 'offline');
    } else if (message.event === 'already_connected') {
        log('Party Id already connected', 'warning');
        UI.connectBtn.disabled = true;
        UI.startProtocolBtn.disabled = true;
        UI.runKeygenBtn.disabled = true;
        UI.checkReadinessBtn.disabled = true;
    } else if (message.event === 'identified') {
        log(`Connected to server as Party ${demoState.partyId}`, 'success');
        updateConnectionStatus(true);
        demoState.reconnectAttempts = 0;
        demoState.isReconnecting = false;
        UI.connectBtn.textContent = '🔗 Connected';
        UI.connectBtn.disabled = true;
        UI.startProtocolBtn.disabled = false;
        UI.runKeygenBtn.disabled = false;
        UI.checkReadinessBtn.disabled = false;
        signalPartyReady('waiting');
        setTimeout(() => checkPartyReadiness(), 500);
    }
}

// Handle party joining
function handlePartyJoined(message) {
    const { partyId } = message;
    demoState.connectedParties.add(partyId);
    updatePartyStatus(partyId, 'online');
    log(`Party ${partyId} joined the session`, 'success');
}

// Handle party leaving
function handlePartyLeft(message) {
    const { partyId } = message;
    demoState.connectedParties.delete(partyId);
    updatePartyStatus(partyId, 'offline');
    log(`Party ${partyId} left the session`, 'warning');
}

// Handle protocol messages
function handleProtocolMessage(message) {
    const { phase, round, sender, data } = message;

    if (sender === demoState.partyId) {
        return; // Ignore our own messages
    }

    log(`Received ${phase} Round ${round} message from Party ${sender}`, 'info');

    // Store the message for the worker
    const roundKey = `${phase}-${round}`;
    if (!demoState.roundData.has(roundKey)) {
        demoState.roundData.set(roundKey, []);
    }

    demoState.roundData.get(roundKey).push({
        sender,
        data
    });

    // Forward to worker if it's for the current phase/round
    if (phase === demoState.currentPhase && round === demoState.currentRound) {
        demoState.worker.postMessage({
            type: 'protocol_message',
            phase,
            round,
            sender,
            data
        });
    }
}

// Handle phase synchronization
function handlePhaseSync(message) {
    const { phase, parties } = message;
    log(`Phase sync: ${parties.length} parties ready for ${phase}`, 'info');

    if (parties.length >= CONFIG.threshold) {
        log(`Sufficient parties for ${phase}, proceeding...`, 'success');
    }
}

// Handle ready status response
function handleReadyStatus(message) {
    const { session } = message;
    log(`Session ${session.id}: ${session.parties.filter(p => p.ready).length}/${session.totalParties} parties ready for ${session.currentPhase}`, 'info');

    // Update party status in UI based on readiness
    session.parties.forEach(party => {
        const status = party.ready ? 'active' : 'online';
        const readyText = party.ready ? `Ready (${party.currentPhase})` : 'Connected';
        updatePartyStatus(party.id, status, readyText);
    });

    // Update connection status with session info
    const readyCount = session.parties.filter(p => p.ready).length;
    const statusText = `Connected - ${readyCount}/${session.totalParties} parties ready`;
    updateConnectionStatus(true, statusText);

    // Enable/disable protocol buttons based on readiness
    const allReady = readyCount >= CONFIG.threshold;
    if (allReady && session.currentPhase === 'waiting') {
        log(`✅ Sufficient parties ready! You can start the protocol.`, 'success');
    } else if (readyCount < CONFIG.threshold) {
        log(`⏳ Waiting for more parties... Need ${CONFIG.threshold - readyCount} more`, 'warning');
    }
}

// Check party readiness
function checkPartyReadiness() {
    if (demoState.websocket && demoState.websocket.readyState === WebSocket.OPEN) {
        sendMessage({
            type: 'ready_check'
        });
        log('Checking party readiness...', 'info');
    } else {
        log('Cannot check readiness: not connected to server', 'error');
    }
}

// Send party readiness signal
function signalPartyReady(phase = 'waiting') {
    if (demoState.websocket && demoState.websocket.readyState === WebSocket.OPEN) {
        sendMessage({
            type: 'phase_sync',
            phase: phase,
            ready: true
        });
        log(`Signaled ready for ${phase} phase`, 'info');
    }
}

// Send message via WebSocket
function sendMessage(message) {
    if (demoState.websocket && demoState.websocket.readyState === WebSocket.OPEN) {
        message.sender = demoState.partyId;
        message.timestamp = Date.now();
        demoState.websocket.send(JSON.stringify(message));
    } else {
        log('Cannot send message: not connected to server', 'error');
    }
}

// Send protocol round message
function sendRoundMessage(data) {
    sendMessage({
        type: 'protocol_message',
        phase: data.phase,
        round: data.round,
        data: data.message
    });
}

// Handle phase completion from worker
function handlePhaseComplete(data) {
    const { phase, result } = data;

    updatePhaseIndicator(phase, 'completed');
    log(`${phase.charAt(0).toUpperCase() + phase.slice(1)} phase completed successfully`, 'success');

    switch (phase) {
        case 'keygen':
            demoState.keyShares = result.incompleteKeyShares;
            updateProgress(33, 'Key generation completed');

            if (demoState.currentPhase === 'keygen') {
                // Auto-start aux generation
                setTimeout(() => startAuxGeneration(), 1000);
            }
            break;

        case 'auxgen':
            demoState.keyShares = result.completeKeyShares;
            updateProgress(66, 'Auxiliary generation completed');

            if (demoState.currentPhase === 'auxgen') {
                // Auto-start signing
                setTimeout(() => startSigning(), 1000);
            }
            break;

        case 'signing':
            displayResults(result);
            updateProgress(100, 'Protocol completed successfully!');
            demoState.currentPhase = 'completed';
            UI.startProtocolBtn.disabled = false;
            UI.runKeygenBtn.disabled = false;
            UI.runSigningBtn.disabled = false;
            break;
    }
}

// Start full protocol
async function startFullProtocol() {
    if (!await initializeWasm()) return;

    demoState.reset();
    demoState.sessionId = `demo-${Date.now()}`;

    log('🚀 Starting full CGGMP21 protocol', 'info');
    updateProgress(0, 'Starting protocol...');

    // Reset UI
    updatePhaseIndicator('keygen', 'pending');
    updatePhaseIndicator('auxgen', 'pending');
    updatePhaseIndicator('signing', 'pending');
    UI.resultsSection.style.display = 'none';

    // Disable buttons during protocol
    UI.startProtocolBtn.disabled = true;
    UI.runKeygenBtn.disabled = true;
    UI.runSigningBtn.disabled = true;

    startKeyGeneration();
}

// Start key generation phase
function startKeyGeneration() {
    demoState.currentPhase = 'keygen';
    demoState.currentRound = 1;

    updatePhaseIndicator('keygen', 'active');
    updateProgress(10, 'Starting key generation...');

    log('Phase 1: Key Generation started', 'info');

    demoState.worker.postMessage({
        type: 'start_keygen',
        config: {
            partyId: demoState.partyId,
            threshold: CONFIG.threshold,
            totalParties: CONFIG.totalParties,
            sessionId: demoState.sessionId + '-keygen'
        }
    });
}

// Start auxiliary generation phase
function startAuxGeneration() {
    if (!demoState.keyShares) {
        log('Cannot start aux generation: no key shares available', 'error');
        return;
    }

    demoState.currentPhase = 'auxgen';
    demoState.currentRound = 1;

    updatePhaseIndicator('auxgen', 'active');
    updateProgress(40, 'Starting auxiliary generation...');

    log('Phase 2: Auxiliary Generation started', 'info');

    demoState.worker.postMessage({
        type: 'start_auxgen',
        config: {
            partyId: demoState.partyId,
            threshold: CONFIG.threshold,
            totalParties: CONFIG.totalParties,
            sessionId: demoState.sessionId + '-auxgen',
            keyShares: demoState.keyShares
        }
    });
}

// Start signing phase
function startSigning() {
    if (!demoState.keyShares) {
        log('Cannot start signing: no complete key shares available', 'error');
        return;
    }

    demoState.currentPhase = 'signing';
    demoState.currentRound = 1;

    updatePhaseIndicator('signing', 'active');
    updateProgress(70, 'Starting threshold signing...');

    log('Phase 3: Threshold Signing started', 'info');

    const messageToSign = UI.messageToSignInput.value || 'Hello, World!';
    const messageHex = Array.from(new TextEncoder().encode(messageToSign))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    demoState.worker.postMessage({
        type: 'start_signing',
        config: {
            partyId: demoState.partyId,
            signingParties: [0, 1], // First two parties sign
            sessionId: demoState.sessionId + '-signing',
            messageHex: messageHex,
            keyShares: demoState.keyShares
        }
    });
}

// Display final results
function displayResults(results) {
    UI.resultsSection.style.display = 'block';
    UI.resultsSection.classList.add('success');

    let html = '<h4>✅ Protocol Execution Successful!</h4>';

    if (results.signatures && results.signatures.length > 0) {
        html += '<p><strong>Signatures Generated:</strong> ' + results.signatures.length + '</p>';

        if (results.verificationResults) {
            const validCount = results.verificationResults.filter(r => r.isValid).length;
            html += '<p><strong>Verification:</strong> ' + validCount + '/' + results.verificationResults.length + ' signatures valid</p>';
        }

        // Display first signature
        html += '<p><strong>Sample Signature:</strong></p>';
        html += '<div class="signature-display">' + results.signatures[0] + '</div>';
    }

    if (results.publicKey) {
        html += '<p><strong>Public Key:</strong></p>';
        html += '<div class="signature-display">' + results.publicKey + '</div>';
    }

    html += '<p style="margin-top: 15px; color: #48bb78;"><strong>🎉 Demonstration completed successfully!</strong></p>';

    UI.resultsContent.innerHTML = html;

    log('All results displayed successfully', 'success');
}

// Reset the demo
function resetDemo() {
    demoState.reset();

    // Reset UI
    updateProgress(0, 'Ready to start protocol');
    updatePhaseIndicator('keygen', 'pending');
    updatePhaseIndicator('auxgen', 'pending');
    updatePhaseIndicator('signing', 'pending');

    UI.resultsSection.style.display = 'none';
    UI.resultsSection.classList.remove('success');

    // Clear logs
    UI.logSection.innerHTML = `
        <div class="log-entry info">[System] Demo reset - ready for new protocol execution</div>
    `;

    // Re-enable buttons
    UI.startProtocolBtn.disabled = !demoState.websocket || demoState.websocket.readyState !== WebSocket.OPEN;
    UI.runKeygenBtn.disabled = !demoState.websocket || demoState.websocket.readyState !== WebSocket.OPEN;
    UI.runSigningBtn.disabled = true; // Only enable after keygen
    UI.checkReadinessBtn.disabled = !demoState.websocket || demoState.websocket.readyState !== WebSocket.OPEN;

    log('Demo reset completed', 'success');
}

// Event listeners
document.addEventListener('DOMContentLoaded', async () => {
    log('CGGMP21 Threshold Secret Sharing Demo Initializing...', 'info');

    // Initialize WASM and worker
    await initializeWasm();
    initializeWorker();

    // Party ID change handler
    UI.partyIdInput.addEventListener('change', (e) => {
        const newPartyId = parseInt(e.target.value);
        if (newPartyId >= 0 && newPartyId < CONFIG.totalParties) {
            demoState.partyId = newPartyId;
            log(`Party ID changed to ${newPartyId}`, 'info');

            // Update party cards to highlight current party
            Object.keys(UI.partyCards).forEach(id => {
                const card = UI.partyCards[id];
                if (parseInt(id) === newPartyId) {
                    card.style.border = '3px solid #667eea';
                } else {
                    card.style.border = '';
                }
            });
        }
    });

    // Button event listeners
    UI.connectBtn.addEventListener('click', connectToServer);
    UI.startProtocolBtn.addEventListener('click', startFullProtocol);
    UI.runKeygenBtn.addEventListener('click', () => {
        resetDemo();
        startKeyGeneration();
    });
    UI.runSigningBtn.addEventListener('click', startSigning);
    UI.checkReadinessBtn.addEventListener('click', checkPartyReadiness);
    UI.resetBtn.addEventListener('click', resetDemo);

    // Set initial party highlight
    const initialPartyId = parseInt(UI.partyIdInput.value);
    demoState.partyId = initialPartyId;
    UI.partyCards[initialPartyId].style.border = '3px solid #667eea';

    log('Demo initialized successfully - click "Connect to Server" to begin', 'success');
});

// Export for debugging
window.demoState = demoState;
window.log = log; 
