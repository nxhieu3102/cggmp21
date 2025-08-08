// test_hierarchical_demo.js - Interactive Demo Main Thread
import init, { 
    StatefulHierarchicalThresholdKeygenProtocol, 
    StatefulAuxGenProtocol,
    StatefulSigningProtocol
} from '../pkg/cggmp21_wasm.js';

// Configuration
const MESSAGE_TO_SIGN = "48656c6c6f2c20576f726c6421"; // "Hello, World!" in hex

// Party configuration
const parties = [
    { i: 0, t: 3, ranks: [0, 0, 1, 1], n: 4, sid: "demo-session", reliable_broadcast_enforced: false, hd_enabled: false, ids: [1, 2, 3] },
    { i: 1, t: 3, ranks: [0, 0, 1, 1], n: 4, sid: "demo-session", reliable_broadcast_enforced: false, hd_enabled: false, ids: [0, 2, 3] },
    { i: 2, t: 3, ranks: [0, 0, 1, 1], n: 4, sid: "demo-session", reliable_broadcast_enforced: false, hd_enabled: false, ids: [0, 1, 3] },
    { i: 3, t: 3, ranks: [0, 0, 1, 1], n: 4, sid: "demo-session", reliable_broadcast_enforced: false, hd_enabled: false, ids: [0, 1, 2] }
];

// Global state
let wasmInitialized = false;
let completeKeyShares = null;
let selectedSigningParties = [];
let isGenerating = false;
let isSigning = false;
let startTime = null;

// DOM Elements
const domElements = {
    generateBtn: null,
    resetBtn: null,
    progressBar: null,
    progressText: null,
    progressLabel: null,
    globalLog: null,
    signatureResult: null,
    signatureValue: null,
    signingTime: null,
    totalTime: null,
    signersCount: null,
    partyElements: []
};

// Initialize DOM elements
function initializeDOMElements() {
    domElements.generateBtn = document.getElementById('generateBtn');
    domElements.resetBtn = document.getElementById('resetBtn');
    domElements.progressBar = document.getElementById('progressBar');
    domElements.progressText = document.getElementById('progressText');
    domElements.progressLabel = document.getElementById('progressLabel');
    domElements.globalLog = document.getElementById('globalLog');
    domElements.signatureResult = document.getElementById('signatureResult');
    domElements.signatureValue = document.getElementById('signatureValue');
    domElements.signingTime = document.getElementById('signingTime');
    domElements.totalTime = document.getElementById('totalTime');
    domElements.signersCount = document.getElementById('signersCount');

    // Initialize party elements
    for (let i = 0; i < 4; i++) {
        domElements.partyElements.push({
            box: document.getElementById(`party${i}`),
            log: document.getElementById(`log${i}`),
            signBtn: document.getElementById(`signBtn${i}`),
            status: document.getElementById(`status${i}`)
        });
    }
}

// Worker Manager
class DemoWorkerManager {
    constructor() {
        this.worker = null;
        this.messageId = 0;
        this.pendingMessages = new Map();
        this.progressCallback = null;
    }

    async initialize() {
        try {
            this.worker = new Worker('./test_hierarchical_demo_worker.js', { type: 'module' });
            this.worker.onmessage = this.handleWorkerMessage.bind(this);
            this.worker.onerror = this.handleWorkerError.bind(this);
            
            // Initialize worker
            await this.sendMessage('init');
            logGlobal("✅ Worker initialized successfully", "success");
        } catch (error) {
            console.error("Failed to initialize worker:", error);
            logGlobal("⚠️ Worker initialization failed, using main thread", "error");
            this.worker = null;
        }
    }

    handleWorkerMessage(e) {
        const { type, data, messageId } = e.data;
        
        if (type === 'progress') {
            if (this.progressCallback) {
                this.progressCallback(data);
            }
            return;
        }

        if (messageId && this.pendingMessages.has(messageId)) {
            const { resolve, reject } = this.pendingMessages.get(messageId);
            this.pendingMessages.delete(messageId);
            
            if (type === 'error') {
                reject(new Error(data.message));
            } else {
                resolve(data);
            }
        }
    }

    handleWorkerError(error) {
        logGlobal(`Worker error: ${error.message}`, "error");
        for (const { reject } of this.pendingMessages.values()) {
            reject(new Error('Worker error: ' + error.message));
        }
        this.pendingMessages.clear();
    }

    async sendMessage(type, data = null) {
        if (!this.worker) {
            // Fallback to main thread
            return await this.executeInMainThread(type, data);
        }

        const messageId = ++this.messageId;
        
        return new Promise((resolve, reject) => {
            this.pendingMessages.set(messageId, { resolve, reject });
            this.worker.postMessage({ type, data, messageId });
        });
    }

    async executeInMainThread(type, data) {
        // Main thread fallback implementation
        switch (type) {
            case 'init':
                await initializeWasm();
                return {};
            case 'run_keygen_auxgen':
                return await runKeygenAuxgenMainThread();
            case 'run_signing':
                return await runSigningMainThread(data.signers, data.keyShares);
            default:
                throw new Error(`Unknown message type: ${type}`);
        }
    }

    setProgressCallback(callback) {
        this.progressCallback = callback;
    }

    terminate() {
        if (this.worker) {
            this.worker.terminate();
            this.worker = null;
        }
        this.pendingMessages.clear();
    }
}

// Create worker manager instance
const workerManager = new DemoWorkerManager();

// Logging functions
function logParty(partyIdx, message, type = "info") {
    if (partyIdx >= 0 && partyIdx < 4) {
        const logEl = domElements.partyElements[partyIdx].log;
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        const timestamp = new Date().toLocaleTimeString('en-US', { 
            hour12: false, 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit',
            fractionalSecondDigits: 3
        });
        entry.textContent = `[${timestamp}] ${message}`;
        logEl.appendChild(entry);
        logEl.scrollTop = logEl.scrollHeight;
    }
}

function logGlobal(message, type = "info") {
    const logEl = domElements.globalLog;
    const timestamp = new Date().toLocaleTimeString('en-US', { 
        hour12: false, 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit'
    });
    
    const colorMap = {
        'success': '#4CAF50',
        'error': '#f44336',
        'info': '#2196F3',
        'warning': '#ff9800'
    };
    
    const color = colorMap[type] || '#d4d4d4';
    const prefix = type === 'success' ? '✅' : type === 'error' ? '❌' : type === 'warning' ? '⚠️' : '📍';
    
    logEl.innerHTML += `<span style="color: ${color}">[${timestamp}] ${prefix} ${message}</span>\n`;
    logEl.scrollTop = logEl.scrollHeight;
}

function updateProgress(percent, label) {
    domElements.progressBar.style.width = `${percent}%`;
    domElements.progressText.textContent = `${Math.round(percent)}%`;
    domElements.progressLabel.textContent = label;
}

function setPartyStatus(partyIdx, status) {
    const statusEl = domElements.partyElements[partyIdx].status;
    statusEl.className = `party-status ${status}`;
}

function setPartyBoxState(partyIdx, state) {
    const box = domElements.partyElements[partyIdx].box;
    box.className = `party-box ${state}`;
}

// Initialize WASM
async function initializeWasm() {
    if (!wasmInitialized) {
        await init();
        wasmInitialized = true;
    }
}

// Helper functions for message routing
function createRecipientMap(items, partyConfig) {
    const map = {};
    items.forEach((item, idx) => {
        map[idx] = items.filter((_, idx2) => partyConfig[idx].ids.includes(idx2));
    });
    return map;
}

function createUnicastMap(unicastMessages, partyConfig) {
    const map = {};
    
    partyConfig.forEach((_, idx) => {
        map[idx] = [];
    });
    
    unicastMessages.forEach((partyMessages, senderIdx) => {
        if (Array.isArray(partyMessages)) {
            partyMessages.forEach((unicastMsg) => {
                const recipientIdx = Array.isArray(unicastMsg) ? unicastMsg[0] : unicastMsg.recipient;
                const message = Array.isArray(unicastMsg) ? unicastMsg[1] : unicastMsg.msg;
                
                if (map[recipientIdx] !== undefined) {
                    map[recipientIdx].push(message);
                }
            });
        }
    });
    
    return map;
}

function createP2PMap(p2pMessages, parties) {
    const map = {};
    
    parties.forEach((_, idx) => {
        map[idx] = [];
    });
    
    p2pMessages.forEach((partyMessages, senderIdx) => {
        partyMessages.forEach(p2pMsg => {
            map[p2pMsg.recipient].push(p2pMsg.message);
        });
    });
    
    return map;
}

// Main thread implementations
async function runKeygenAuxgenMainThread() {
    // Phase 1: Key Generation
    logGlobal("Starting Key Generation Phase", "info");
    updateProgress(5, "Initializing key generation protocols...");
    
    const keygenProtocols = [];
    for (let i = 0; i < parties.length; i++) {
        logParty(i, "Initializing protocol...", "info");
        setPartyStatus(i, "busy");
        const protocol = new StatefulHierarchicalThresholdKeygenProtocol(parties[i]);
        keygenProtocols.push(protocol);
        logParty(i, "Protocol initialized", "success");
    }
    
    // Round 1: Commitments
    updateProgress(15, "Round 1: Generating commitments...");
    logGlobal("Round 1: Generating commitments", "info");
    
    const commitments = keygenProtocols.map((protocol, idx) => {
        logParty(idx, "Generating commitment...", "info");
        const commitment = protocol.round1_generate_commitment();
        logParty(idx, "Commitment generated", "success");
        return commitment;
    });
    
    const commitmentsMap = createRecipientMap(commitments, parties);
    keygenProtocols.forEach((protocol, idx) => {
        protocol.set_round1_commitments({
            commitments: commitmentsMap[idx],
            ids: parties[idx].ids
        });
        logParty(idx, `Received ${commitmentsMap[idx].length} commitments`, "info");
    });
    
    // Round 2: Decommitments and shares
    updateProgress(30, "Round 2: Generating decommitments and shares...");
    logGlobal("Round 2: Generating decommitments and shares", "info");
    
    const decommitments = keygenProtocols.map((protocol, idx) => {
        logParty(idx, "Generating decommitment...", "info");
        return protocol.round2_get_decommitment();
    });
    
    const unicastMessages = keygenProtocols.map((protocol, idx) => {
        logParty(idx, "Generating secret shares...", "info");
        return protocol.round2_get_unicast_messages();
    });
    
    const decommitmentsMap = createRecipientMap(decommitments, parties);
    const sigmasMap = createUnicastMap(unicastMessages, parties);
    
    keygenProtocols.forEach((protocol, idx) => {
        protocol.set_round2_decommitments({
            decommitments: decommitmentsMap[idx],
            ids: parties[idx].ids
        });
        protocol.set_round2_sigmas({
            sigmas: sigmasMap[idx],
            ids: parties[idx].ids
        });
        logParty(idx, "Validating round 2 data...", "info");
        protocol.validate_round2_and_prepare_round3();
        logParty(idx, "Round 2 validation complete", "success");
    });
    
    // Round 3: Schnorr proofs
    updateProgress(45, "Round 3: Generating Schnorr proofs...");
    logGlobal("Round 3: Generating Schnorr proofs", "info");
    
    const schnorrProofs = keygenProtocols.map((protocol, idx) => {
        logParty(idx, "Generating Schnorr proof...", "info");
        const proof = protocol.round3_generate_proof();
        logParty(idx, "Schnorr proof generated", "success");
        return proof;
    });
    
    const proofsMap = createRecipientMap(schnorrProofs, parties);
    keygenProtocols.forEach((protocol, idx) => {
        protocol.set_round3_schnorr_proofs({
            sch_proof: proofsMap[idx],
            ids: parties[idx].ids
        });
        logParty(idx, "Schnorr proofs verified", "success");
    });
    
    // Finalize key generation
    updateProgress(60, "Finalizing key generation...");
    const incompleteKeyShares = keygenProtocols.map((protocol, idx) => {
        logParty(idx, "Generating key share...", "info");
        const keyShare = protocol.finalize_key_generation();
        logParty(idx, `Key share generated (rank ${parties[idx].ranks[idx]})`, "success");
        return keyShare;
    });
    
    logGlobal("Key generation completed successfully!", "success");
    
    // Phase 2: Auxiliary Generation
    updateProgress(65, "Starting Auxiliary Generation Phase...");
    logGlobal("Starting Auxiliary Generation Phase", "info");
    
    const auxGenProtocols = await Promise.all(
        parties.map(async (party, idx) => {
            logParty(idx, "Initializing auxiliary protocol...", "info");
            const protocol = await new StatefulAuxGenProtocol({
                ...party,
                sid: party.sid + "-auxgen",
                compute_multiexp_table: false,
                compute_crt: false
            });
            logParty(idx, "Auxiliary protocol initialized", "success");
            return protocol;
        })
    );
    
    // Aux Round 1
    updateProgress(75, "Auxiliary Round 1: Generating commitments...");
    const auxCommitments = auxGenProtocols.map((protocol, idx) => {
        logParty(idx, "Generating auxiliary commitment...", "info");
        return protocol.round1_generate_commitment();
    });
    
    const auxCommitmentsMap = createRecipientMap(auxCommitments, parties);
    auxGenProtocols.forEach((protocol, idx) => {
        protocol.set_round1_commitments({
            commitments: auxCommitmentsMap[idx],
            ids: parties[idx].ids
        });
    });
    
    // Aux Round 2
    updateProgress(85, "Auxiliary Round 2: Processing decommitments...");
    const auxDecommitments = auxGenProtocols.map((protocol, idx) => {
        return protocol.round2_get_decommitment();
    });
    
    const auxDecommitmentsMap = createRecipientMap(auxDecommitments, parties);
    auxGenProtocols.forEach((protocol, idx) => {
        protocol.set_round2_decommitments({
            decommitments: auxDecommitmentsMap[idx],
            ids: parties[idx].ids
        });
        protocol.validate_round2_decommitments();
    });
    
    // Aux Round 3
    updateProgress(90, "Auxiliary Round 3: Finalizing...");
    const round3Messages = auxGenProtocols.map((protocol, idx) => {
        logParty(idx, "Creating auxiliary messages...", "info");
        return protocol.round3_create_messages();
    });
    
    auxGenProtocols.forEach((protocol, idx) => {
        const messagesForParty = [];
        round3Messages.forEach((msgs, senderIdx) => {
            if (senderIdx !== idx && parties[idx].ids.includes(senderIdx)) {
                if (Array.isArray(msgs)) {
                    msgs.forEach(msgPair => {
                        if (Array.isArray(msgPair) && msgPair.length === 2) {
                            const [recipientId, message] = msgPair;
                            if (recipientId === idx) {
                                messagesForParty.push(message);
                            }
                        }
                    });
                }
            }
        });
        
        protocol.set_round3_messages({
            messages: messagesForParty,
            ids: parties[idx].ids
        });
    });
    
    const auxInfos = auxGenProtocols.map((protocol, idx) => {
        const auxInfo = protocol.finalize();
        logParty(idx, "Auxiliary information generated", "success");
        setPartyStatus(idx, "ready");
        return auxInfo;
    });
    
    // Create complete key shares
    const completeShares = incompleteKeyShares.map((incompleteShare, idx) => {
        return {
            core: incompleteShare,
            aux: auxInfos[idx],
            party_index: idx,
            rank: parties[idx].ranks[idx]
        };
    });
    
    updateProgress(100, "Key generation and auxiliary setup complete!");
    logGlobal("✅ All parties ready for signing!", "success");
    
    return { completeKeyShares: completeShares };
}

async function runSigningMainThread(signers, keyShares) {
    const signingStartTime = Date.now();
    
    logGlobal(`Starting signing protocol with parties: [${signers.join(', ')}]`, "info");
    updateProgress(10, "Initializing signing protocol...");
    
    // Validate signing set
    const signerRanks = signers.map(idx => parties[idx].ranks[idx]).sort((a, b) => a - b);
    const isValidSigningSet = signerRanks.every((rank, idx) => rank <= idx);
    
    if (!isValidSigningSet) {
        throw new Error(`Invalid signing set: ranks [${signerRanks.join(', ')}] violate hierarchical constraints`);
    }
    
    logGlobal(`Valid signing set with ranks: [${signerRanks.join(', ')}]`, "success");
    
    // Get key shares for signers
    const signingKeyShares = signers.map(idx => keyShares[idx]);
    
    // Create signing protocols
    const signingProtocols = signers.map((globalIdx, localIdx) => {
        logParty(globalIdx, "Initializing signing protocol...", "info");
        setPartyStatus(globalIdx, "busy");
        
        const protocol = new StatefulSigningProtocol({
            i: localIdx,
            signing_parties: signers.map((_, i) => i),
            sid: parties[globalIdx].sid + "-signing",
            reliable_broadcast_enforced: false,
            message_hex: MESSAGE_TO_SIGN,
            enable_precomputable: false
        }, signingKeyShares[localIdx]);
        
        logParty(globalIdx, "Signing protocol ready", "success");
        return protocol;
    });
    
    // Round 1a
    updateProgress(25, "Round 1a: Generating broadcast messages...");
    const round1aMessages = signingProtocols.map((protocol, localIdx) => {
        const globalIdx = signers[localIdx];
        logParty(globalIdx, "Generating round 1a message...", "info");
        return protocol.round1a_generate_message();
    });
    
    signingProtocols.forEach((protocol, localIdx) => {
        const otherMessages = round1aMessages.filter((_, msgIdx) => msgIdx !== localIdx);
        const otherIds = signers.filter((_, idx) => idx !== localIdx).map((_, i) => i);
        protocol.set_round1a_messages({
            messages: otherMessages,
            ids: otherIds
        });
    });
    
    // Round 1b
    updateProgress(40, "Round 1b: Generating P2P messages...");
    const round1bMessages = signingProtocols.map((protocol, localIdx) => {
        const globalIdx = signers[localIdx];
        logParty(globalIdx, "Generating round 1b messages...", "info");
        return protocol.round1b_generate_messages();
    });
    
    const round1bMap = createP2PMap(round1bMessages, signers.map((_, i) => i));
    signingProtocols.forEach((protocol, localIdx) => {
        protocol.set_round1b_messages({
            messages: round1bMap[localIdx],
            ids: signers.filter((_, idx) => idx !== localIdx).map((_, i) => i)
        });
        protocol.validate_round1b_proofs();
        const globalIdx = signers[localIdx];
        logParty(globalIdx, "Round 1b proofs validated", "success");
    });
    
    // Round 2
    updateProgress(55, "Round 2: Generating P2P messages...");
    const round2Messages = signingProtocols.map((protocol, localIdx) => {
        const globalIdx = signers[localIdx];
        logParty(globalIdx, "Generating round 2 messages...", "info");
        return protocol.round2_generate_messages();
    });
    
    const round2Map = createP2PMap(round2Messages, signers.map((_, i) => i));
    signingProtocols.forEach((protocol, localIdx) => {
        protocol.set_round2_messages({
            messages: round2Map[localIdx],
            ids: signers.filter((_, idx) => idx !== localIdx).map((_, i) => i)
        });
    });
    
    // Round 3
    updateProgress(70, "Round 3: Generating P2P messages...");
    const round3Messages = signingProtocols.map((protocol, localIdx) => {
        const globalIdx = signers[localIdx];
        logParty(globalIdx, "Generating round 3 messages...", "info");
        return protocol.round3_generate_messages();
    });
    
    const round3Map = createP2PMap(round3Messages, signers.map((_, i) => i));
    signingProtocols.forEach((protocol, localIdx) => {
        protocol.set_round3_messages({
            messages: round3Map[localIdx],
            ids: signers.filter((_, idx) => idx !== localIdx).map((_, i) => i)
        });
    });
    
    // Generate presignatures
    updateProgress(80, "Generating presignatures...");
    const presignatures = signingProtocols.map((protocol, localIdx) => {
        const globalIdx = signers[localIdx];
        logParty(globalIdx, "Generating presignature...", "info");
        return protocol.generate_presignature();
    });
    
    // Round 4
    updateProgress(90, "Round 4: Generating partial signatures...");
    const round4Messages = signingProtocols.map((protocol, localIdx) => {
        const globalIdx = signers[localIdx];
        logParty(globalIdx, "Generating partial signature...", "info");
        return protocol.round4_generate_message();
    });
    
    const round4Map = createRecipientMap(
        round4Messages.map(msg => (msg !== undefined && msg !== null) ? msg : {}),
        signers.map((_, idx) => ({ ids: signers.filter((_, i) => i !== idx).map((_, j) => j) }))
    );
    
    signingProtocols.forEach((protocol, localIdx) => {
        if (round4Map[localIdx] && round4Map[localIdx].length > 0) {
            protocol.set_round4_messages({
                messages: round4Map[localIdx],
                ids: signers.filter((_, idx) => idx !== localIdx).map((_, i) => i)
            });
        }
    });
    
    // Generate final signatures
    updateProgress(95, "Generating final signatures...");
    const signatures = signingProtocols.map((protocol, localIdx) => {
        const round4Msg = round4Messages[localIdx];
        if (round4Msg !== undefined && round4Msg !== null) {
            const globalIdx = signers[localIdx];
            logParty(globalIdx, "Generating final signature...", "info");
            const sig = protocol.generate_signature(round4Msg);
            logParty(globalIdx, "Signature generated!", "success");
            setPartyStatus(globalIdx, "ready");
            return sig;
        }
        return null;
    });
    
    const validSignatures = signatures.filter(sig => sig !== null);
    
    // Verify signature
    updateProgress(98, "Verifying signature...");
    if (validSignatures.length > 0) {
        const publicKeyHex = StatefulSigningProtocol.get_public_key_from_keyshare(keyShares[0]);
        const signature = validSignatures[0];
        const isValid = StatefulSigningProtocol.verify_signature(signature, publicKeyHex, MESSAGE_TO_SIGN);
        
        if (isValid) {
            logGlobal("✅ Signature verification: VALID", "success");
        } else {
            logGlobal("❌ Signature verification: INVALID", "error");
        }
        
        const signingEndTime = Date.now();
        const signingTime = signingEndTime - signingStartTime;
        
        return {
            signature,
            isValid,
            signingTime,
            signers
        };
    }
    
    throw new Error("No valid signatures generated");
}

// Event handlers
async function handleGenerateClick() {
    if (isGenerating) return;
    
    isGenerating = true;
    startTime = Date.now();
    domElements.generateBtn.disabled = true;
    domElements.generateBtn.textContent = "🔄 Generating...";
    
    // Clear party logs
    for (let i = 0; i < 4; i++) {
        domElements.partyElements[i].log.innerHTML = '';
        setPartyStatus(i, '');
    }
    
    // Hide signature result
    domElements.signatureResult.classList.remove('show');
    
    try {
        logGlobal("🚀 Starting key generation and auxiliary setup...", "info");
        const result = await workerManager.sendMessage('run_keygen_auxgen');
        completeKeyShares = result.completeKeyShares;
        
        // Enable sign buttons
        for (let i = 0; i < 4; i++) {
            domElements.partyElements[i].signBtn.disabled = false;
        }
        
        const endTime = Date.now();
        const totalTime = ((endTime - startTime) / 1000).toFixed(2);
        logGlobal(`✅ Setup complete in ${totalTime}s. Select 3 parties to sign.`, "success");
        
    } catch (error) {
        logGlobal(`❌ Generation failed: ${error.message}`, "error");
        console.error(error);
    } finally {
        isGenerating = false;
        domElements.generateBtn.disabled = false;
        domElements.generateBtn.textContent = "🔑 Generate Key Shares";
        updateProgress(0, "Ready for signing");
    }
}

async function handleSignClick(partyIdx) {
    if (isSigning || !completeKeyShares) return;
    
    // Add to selected parties
    selectedSigningParties.push(partyIdx);
    
    // Update UI
    domElements.partyElements[partyIdx].signBtn.disabled = true;
    domElements.partyElements[partyIdx].signBtn.classList.add('selected');
    domElements.partyElements[partyIdx].signBtn.textContent = `✅ Selected (${selectedSigningParties.length}/3)`;
    setPartyBoxState(partyIdx, 'selected');
    
    logGlobal(`Party ${partyIdx} selected for signing (${selectedSigningParties.length}/3)`, "info");
    
    // If 3 parties selected, start signing
    if (selectedSigningParties.length === 3) {
        isSigning = true;
        
        // Mark selected parties as signing
        selectedSigningParties.forEach(idx => {
            setPartyBoxState(idx, 'selected signing');
        });
        
        try {
            logGlobal(`🚀 Starting signing protocol with parties [${selectedSigningParties.join(', ')}]...`, "info");
            
            const result = await workerManager.sendMessage('run_signing', {
                signers: selectedSigningParties,
                keyShares: completeKeyShares
            });
            
            // Display results
            domElements.signatureValue.textContent = result.signature;
            domElements.signingTime.textContent = `${(result.signingTime / 1000).toFixed(2)}s`;
            
            const totalTime = ((Date.now() - startTime) / 1000).toFixed(2);
            domElements.totalTime.textContent = `${totalTime}s`;
            domElements.signersCount.textContent = selectedSigningParties.join(', ');
            
            domElements.signatureResult.classList.add('show');
            
            updateProgress(100, "Signature generated successfully!");
            
        } catch (error) {
            logGlobal(`❌ Signing failed: ${error.message}`, "error");
            console.error(error);
        } finally {
            isSigning = false;
            
            // Reset signing state
            selectedSigningParties.forEach(idx => {
                setPartyBoxState(idx, '');
            });
        }
    }
}

function handleReset() {
    // Reset state
    completeKeyShares = null;
    selectedSigningParties = [];
    isGenerating = false;
    isSigning = false;
    startTime = null;
    
    // Reset UI
    updateProgress(0, "Ready to start...");
    domElements.globalLog.innerHTML = '';
    domElements.signatureResult.classList.remove('show');
    
    // Reset party UI
    for (let i = 0; i < 4; i++) {
        domElements.partyElements[i].log.innerHTML = '';
        domElements.partyElements[i].signBtn.disabled = true;
        domElements.partyElements[i].signBtn.classList.remove('selected');
        domElements.partyElements[i].signBtn.textContent = "✍️ Sign Message";
        setPartyStatus(i, '');
        setPartyBoxState(i, '');
    }
    
    logGlobal("Demo reset. Click 'Generate Key Shares' to start.", "info");
}

// Initialize
async function initialize() {
    initializeDOMElements();
    
    // Set up event listeners
    domElements.generateBtn.addEventListener('click', handleGenerateClick);
    domElements.resetBtn.addEventListener('click', handleReset);
    
    for (let i = 0; i < 4; i++) {
        const idx = i;
        domElements.partyElements[i].signBtn.addEventListener('click', () => handleSignClick(idx));
    }
    
    // Initialize worker
    await workerManager.initialize();
    
    // Set up progress callback
    workerManager.setProgressCallback((data) => {
        const { partyIdx, phase, round, message, progress } = data;
        
        if (partyIdx !== null && partyIdx !== undefined) {
            logParty(partyIdx, `${phase}/${round}: ${message}`, "info");
        } else {
            logGlobal(`${phase}: ${message}`, "info");
        }
        
        if (progress !== null) {
            updateProgress(progress, `${phase}: ${message}`);
        }
    });
    
    logGlobal("🔐 Hierarchical CGGMP21 Demo Ready", "success");
    logGlobal("Click 'Generate Key Shares' to begin", "info");
}

// Start when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}

export { initialize, handleGenerateClick, handleSignClick, handleReset };
