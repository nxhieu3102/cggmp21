import init, { 
    StatefulKeygenProtocol, 
    StatefulAuxGenProtocol,
    StatefulSigningProtocol 
} from '../pkg/cggmp21_wasm.js';

// Test configuration for 2-of-3 threshold signing
const parties = [
    {
        i: 0,
        t: 2,
        n: 3,
        sid: "test-signing-session-123",
        reliable_broadcast_enforced: false,
        ids: [1, 2] // Other parties this party communicates with
    },
    {
        i: 1,
        t: 2,
        n: 3,
        sid: "test-signing-session-123", 
        reliable_broadcast_enforced: false,
        ids: [0, 2]
    },
    {
        i: 2,
        t: 2,
        n: 3,
        sid: "test-signing-session-123",
        reliable_broadcast_enforced: false,
        ids: [0, 1]
    }
];

// Message to sign (hex-encoded)
const MESSAGE_TO_SIGN = "48656c6c6f2c20576f726c6421"; // "Hello, World!" in hex

// Global state for WASM initialization
let wasmInitialized = false;

// Web Worker Manager for heavy computations
class WorkerManager {
    constructor() {
        this.worker = null;
        this.messageId = 0;
        this.pendingMessages = new Map();
        this.progressCallback = null;
        this.isWorkerSupported = typeof Worker !== 'undefined';
    }

    async initialize() {
        if (!this.isWorkerSupported) {
            console.log("Web Workers not supported, falling back to main thread");
            return;
        }

        try {
            this.worker = new Worker('./test_worker.js', { type: 'module' });
            this.worker.onmessage = this.handleWorkerMessage.bind(this);
            this.worker.onerror = this.handleWorkerError.bind(this);
            
            // Initialize worker
            await this.sendMessage('init');
            log("🔧 Web Worker initialized successfully", "success");
        } catch (error) {
            console.warn("Failed to initialize Web Worker, falling back to main thread:", error);
            this.worker = null;
        }
    }

    handleWorkerMessage(e) {
        const { type, data, messageId } = e.data;
        
        if (type === 'progress' && this.progressCallback) {
            this.progressCallback(data);
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
        log(`Worker error: ${error.message}`, "error");
        // Reject all pending messages
        for (const { reject } of this.pendingMessages.values()) {
            reject(new Error('Worker error: ' + error.message));
        }
        this.pendingMessages.clear();
    }

    async sendMessage(type, data = null) {
        if (!this.worker) {
            throw new Error("Worker not available");
        }

        const messageId = ++this.messageId;
        
        return new Promise((resolve, reject) => {
            this.pendingMessages.set(messageId, { resolve, reject });
            this.worker.postMessage({ type, data, messageId });
        });
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

// Global worker manager instance
const workerManager = new WorkerManager();

// Browser-specific logging function
function log(message, type = "normal") {
    const timestamp = new Date().toLocaleTimeString();
    let formattedMessage = `[${timestamp}] ${message}`;
    
    // Format message based on type
    if (type === "success") {
        formattedMessage = `[${timestamp}] ✅ ${message}`;
    } else if (type === "error") {
        formattedMessage = `[${timestamp}] ❌ ${message}`;
    } else if (type === "phase") {
        formattedMessage = `\n[${timestamp}] 🔄 ${message}\n${'='.repeat(50)}`;
    } else if (type === "round") {
        formattedMessage = `[${timestamp}] 📍 ${message}`;
    }

    // Log to console
    console.log(formattedMessage);
    
    // If in browser environment, also log to DOM
    if (typeof document !== 'undefined') {
        const output = document.getElementById('output');
        if (output) {
            output.textContent += formattedMessage + '\n';
            output.scrollTop = output.scrollHeight;
        }
    }
}

// Progress bar management
function updateProgressBar(phase, progress, message) {
    if (typeof document === 'undefined') return;
    
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const phaseText = document.getElementById('phaseText');
    
    if (progressBar && progressText && phaseText) {
        if (progress !== null) {
            progressBar.style.width = `${progress}%`;
            progressText.textContent = `${Math.round(progress)}%`;
        }
        phaseText.textContent = `${phase}: ${message}`;
        
        // Change color based on progress
        if (progress >= 100) {
            progressBar.style.backgroundColor = '#28a745'; // Success green
        } else if (progress >= 50) {
            progressBar.style.backgroundColor = '#17a2b8'; // Info blue
        } else {
            progressBar.style.backgroundColor = '#ffc107'; // Warning yellow
        }
    }
}

// Initialize WASM module
async function initializeWasm() {
    if (!wasmInitialized) {
        await init();
        wasmInitialized = true;
        log("WASM module initialized successfully", "success");
    }
}

// Helper functions for message routing (fallback for main thread)
const createRecipientMap = (items, partyConfig) => {
    const map = {};
    items.forEach((item, idx) => {
        map[idx] = items.filter((_, idx2) => partyConfig[idx].ids.includes(idx2));
    });
    return map;
};

const createP2PMap = (p2pMessages, parties) => {
    const map = {};
    
    // Initialize map with empty arrays for each party
    parties.forEach((_, idx) => {
        map[idx] = [];
    });
    
    // Route P2P messages to recipients
    p2pMessages.forEach((partyMessages, senderIdx) => {
        partyMessages.forEach(p2pMsg => {
            map[p2pMsg.recipient].push(p2pMsg.message);
        });
    });
    
    return map;
};

// Worker-based functions (with fallback to main thread)
async function runKeyGeneration() {
    if (workerManager.worker) {
        log("🔧 Running key generation in Web Worker", "phase");
        return await workerManager.sendMessage('run_keygen');
    } else {
        return await runKeyGenerationMainThread();
    }
}

async function runAuxGeneration(incompleteKeyShares) {
    if (workerManager.worker) {
        log("🔧 Running aux generation in Web Worker", "phase");
        return await workerManager.sendMessage('run_auxgen', { incompleteKeyShares });
    } else {
        return await runAuxGenerationMainThread(incompleteKeyShares);
    }
}

async function runSigning(completeKeyShares) {
    if (workerManager.worker) {
        log("🔧 Running signing in Web Worker", "phase");
        return await workerManager.sendMessage('run_signing', { completeKeyShares });
    } else {
        return await runSigningMainThread(completeKeyShares);
    }
}

async function runFullPipelineTest() {
    if (workerManager.worker) {
        log("🔧 Running full pipeline in Web Worker", "phase");
        return await workerManager.sendMessage('run_full_pipeline');
    } else {
        return await runFullPipelineTestMainThread();
    }
}

// Fallback implementations for main thread (for Node.js or when workers fail)
async function runKeyGenerationMainThread() {
    log("Starting Key Generation Phase", "phase");
    
    const keygenProtocols = parties.map(party => 
        new StatefulKeygenProtocol({
            ...party,
            sid: party.sid + "-keygen"
        })
    );
    
    log("Round 1: Generating commitments...", "round");
    const commitments = keygenProtocols.map(protocol => 
        protocol.round1_generate_commitment()
    );
    
    log("Round 2: Broadcasting decommitments and sending sigmas...", "round");
    const decommitments = keygenProtocols.map(protocol => 
        protocol.round2_broad()
    );
    
    const sigmasMsgs = keygenProtocols.map(protocol => 
        protocol.round2_uni()
    );
    
    const sigmasMap = {};
    sigmasMsgs.forEach(msgs => {
        msgs.forEach(msg => {
            const recipient = msg.recipient.OneParty;
            if (!sigmasMap[recipient]) {
                sigmasMap[recipient] = [];
            }
            sigmasMap[recipient].push(msg.msg.Round2Uni);
        });
    });
    
    log("Round 3: Generating Schnorr proofs...", "round");
    const commitmentsMap = createRecipientMap(commitments, parties);
    const decommitmentsMap = createRecipientMap(decommitments, parties);
    
    const round3Msgs = keygenProtocols.map((protocol, idx) => {
        return protocol.round3({
            commitments: commitmentsMap[idx],
            ids: parties[idx].ids
        }, {
            decommitments: decommitmentsMap[idx],
            ids: parties[idx].ids
        }, {
            sigmas: sigmasMap[idx],
            ids: parties[idx].ids
        });
    });
    
    log("Final: Generating incomplete key shares...", "round");
    const schProofMap = createRecipientMap(round3Msgs, parties);
    
    const incompleteKeyShares = keygenProtocols.map((protocol, idx) => {
        return protocol.round_key_share({
            commitments: commitmentsMap[idx],
            ids: parties[idx].ids
        }, {
            decommitments: decommitmentsMap[idx],
            ids: parties[idx].ids
        }, {
            sigmas: sigmasMap[idx],
            ids: parties[idx].ids
        }, {
            sch_proof: schProofMap[idx],
            ids: parties[idx].ids
        });
    });
    
    log(`Key generation completed! Generated ${incompleteKeyShares.length} incomplete key shares`, "success");
    return incompleteKeyShares;
}

async function runAuxGenerationMainThread(incompleteKeyShares) {
    log("Starting Auxiliary Generation Phase", "phase");
    
    const auxGenProtocols = await Promise.all(
        parties.map(party => 
            new StatefulAuxGenProtocol({
                ...party,
                sid: party.sid + "-auxgen",
                compute_multiexp_table: false,
                compute_crt: false
            })
        )
    );
    
    log("Round 1: Generating commitments...", "round");
    const commitments = auxGenProtocols.map(protocol => 
        protocol.round1_generate_commitment()
    );
    
    const commitmentsMap = createRecipientMap(commitments, parties);
    auxGenProtocols.forEach((protocol, idx) => {
        protocol.set_round1_commitments({
            commitments: commitmentsMap[idx],
            ids: parties[idx].ids
        });
    });
    
    log("Round 2: Getting decommitments...", "round");
    const decommitments = auxGenProtocols.map(protocol => 
        protocol.round2_get_decommitment()
    );
    
    const decommitmentsMap = createRecipientMap(decommitments, parties);
    auxGenProtocols.forEach((protocol, idx) => {
        protocol.set_round2_decommitments({
            decommitments: decommitmentsMap[idx],
            ids: parties[idx].ids
        });
        protocol.validate_round2_decommitments();
    });
    
    log("Round 3: Creating messages...", "round");
    const round3Messages = auxGenProtocols.map(protocol => 
        protocol.round3_create_messages()
    );
    
    const round3Map = createP2PMap(round3Messages, parties);
    
    log("Final: Finalizing auxiliary info...", "round");
    const auxInfos = auxGenProtocols.map((protocol, idx) => {
        protocol.set_round3_messages({
            messages: round3Map[idx],
            ids: parties[idx].ids
        });
        return protocol.finalize();
    });
    
    const completeKeyShares = incompleteKeyShares.map((incompleteShare, idx) => {
        return {
            core: incompleteShare,
            aux: auxInfos[idx],
            party_index: idx
        };
    });
    
    log(`Auxiliary generation completed! Generated ${completeKeyShares.length} complete key shares`, "success");
    return completeKeyShares;
}

async function runSigningMainThread(completeKeyShares) {
    log("Starting Signing Phase", "phase");
    
    const signingParties = [0, 1];
    const signingKeyShares = signingParties.map(idx => completeKeyShares[idx]);
    
    const signingProtocols = signingParties.map((globalIdx, localIdx) => 
        new StatefulSigningProtocol({
            i: localIdx,
            signing_parties: [0, 1],
            sid: parties[globalIdx].sid + "-signing",
            reliable_broadcast_enforced: false,
            message_hex: MESSAGE_TO_SIGN
        }, signingKeyShares[localIdx])
    );
    
    log("Round 1a: Generating broadcast messages...", "round");
    const round1aMessages = signingProtocols.map(protocol => 
        protocol.round1a_generate_message()
    );
    
    signingProtocols.forEach((protocol, idx) => {
        const otherMessages = round1aMessages.filter((_, msgIdx) => msgIdx !== idx);
        const otherIds = signingParties.filter((_, partyIdx) => partyIdx !== idx);
        protocol.set_round1a_messages({
            messages: otherMessages,
            ids: otherIds
        });
    });
    
    log("Round 1b: Generating P2P messages...", "round");
    const round1bMessages = signingProtocols.map(protocol => 
        protocol.round1b_generate_messages()
    );
    
    const round1bMap = createP2PMap(round1bMessages, signingParties);
    signingProtocols.forEach((protocol, idx) => {
        protocol.set_round1b_messages({
            messages: round1bMap[idx],
            ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
        });
        protocol.validate_round1b_proofs();
    });
    
    log("Round 2: Generating P2P messages...", "round");
    const round2Messages = signingProtocols.map(protocol => 
        protocol.round2_generate_messages()
    );
    
    const round2Map = createP2PMap(round2Messages, signingParties);
    signingProtocols.forEach((protocol, idx) => {
        protocol.set_round2_messages({
            messages: round2Map[idx],
            ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
        });
    });
    
    log("Round 3: Generating P2P messages...", "round");
    const round3Messages = signingProtocols.map(protocol => 
        protocol.round3_generate_messages()
    );
    
    const round3Map = createP2PMap(round3Messages, signingParties);
    signingProtocols.forEach((protocol, idx) => {
        protocol.set_round3_messages({
            messages: round3Map[idx],
            ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
        });
    });
    
    log("Generating presignatures...", "round");
    const presignatures = signingProtocols.map(protocol => 
        protocol.generate_presignature()
    );
    
    log("Round 4: Generating partial signatures...", "round");
    const round4Messages = signingProtocols.map(protocol => 
        protocol.round4_generate_message()
    );
    
    const round4Map = createRecipientMap(
        round4Messages.map(msg => (msg !== undefined && msg !== null) ? msg : {}), 
        signingParties.map((_, idx) => ({ ids: signingParties.filter((_, partyIdx) => partyIdx !== idx) }))
    );
    
    signingProtocols.forEach((protocol, idx) => {
        if (round4Map[idx] && round4Map[idx].length > 0) {
            protocol.set_round4_messages({
                messages: round4Map[idx],
                ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
            });
        }
    });
    
    log("Final: Generating signatures...", "round");
    const signatures = signingProtocols.map((protocol, idx) => {
        const round4Msg = round4Messages[idx];
        if (round4Msg !== undefined && round4Msg !== null) {
            return protocol.generate_signature(round4Msg);
        }
        return null;
    });
    
    const validSignatures = signatures.filter(sig => sig !== null);
    
    // Verify signatures
    log("Verifying signatures...", "round");
    const verificationResults = [];
    
    if (validSignatures.length > 0) {
        try {
            // Get public key from the first complete key share
            const publicKeyHex = StatefulSigningProtocol.get_public_key_from_keyshare(completeKeyShares[0]);
            log(`Using public key: ${publicKeyHex}`, "round");
            
            for (let i = 0; i < validSignatures.length; i++) {
                const signature = validSignatures[i];
                const isValid = StatefulSigningProtocol.verify_signature(signature, publicKeyHex, MESSAGE_TO_SIGN);
                verificationResults.push({
                    signatureIndex: i,
                    isValid: isValid,
                    signature: signature
                });
                
                if (isValid) {
                    log(`✅ Signature ${i} verification: VALID`, "success");
                } else {
                    log(`❌ Signature ${i} verification: INVALID`, "error");
                }
            }
            
            const validCount = verificationResults.filter(r => r.isValid).length;
            log(`Verification complete: ${validCount}/${verificationResults.length} signatures are valid`, "success");
            
        } catch (error) {
            log(`Error during signature verification: ${error.message}`, "error");
            verificationResults.push({
                error: error.message || error
            });
        }
    }
    
    log(`Signing completed! Generated ${validSignatures.length} signatures`, "success");
    
    return {
        presignatures,
        signatures: validSignatures,
        verificationResults
    };
}

async function runFullPipelineTestMainThread() {
    try {
        await initializeWasm();

        log("🚀 Starting Full CGGMP21 Pipeline Test", "phase");
        log(`Configuration: ${parties[0].t}-of-${parties[0].n} threshold signing`);
        log(`Message to sign: ${MESSAGE_TO_SIGN} ("Hello, World!")`);
        
        const incompleteKeyShares = await runKeyGenerationMainThread();
        const completeKeyShares = await runAuxGenerationMainThread(incompleteKeyShares);
        const signingResults = await runSigningMainThread(completeKeyShares);
        
        log("🎉 Full Pipeline Test Completed Successfully!", "success");
        log(`Results Summary:`, "success");
        log(`- Incomplete key shares: ${incompleteKeyShares.length}`, "success");
        log(`- Complete key shares: ${completeKeyShares.length}`, "success");
        log(`- Presignatures: ${signingResults.presignatures.length}`, "success");
        log(`- Final signatures: ${signingResults.signatures.length}`, "success");
        
        // Log verification results
        if (signingResults.verificationResults && signingResults.verificationResults.length > 0) {
            const validCount = signingResults.verificationResults.filter(r => r.isValid).length;
            const totalCount = signingResults.verificationResults.filter(r => !r.error).length;
            log(`- Signature verification: ${validCount}/${totalCount} signatures verified as VALID`, validCount === totalCount ? "success" : "error");
            
            if (validCount === totalCount && totalCount > 0) {
                log("🔐 All signatures passed cryptographic verification!", "success");
            } else if (validCount > 0) {
                log("⚠️ Some signatures failed verification - check implementation", "error");
            } else {
                log("❌ All signatures failed verification - critical error", "error");
            }
        }
        
        return {
            incompleteKeyShares,
            completeKeyShares,
            signingResults
        };
        
    } catch (error) {
        log(`Pipeline test failed: ${error.message}`, "error");
        log(`Error details: ${error.stack}`, "error");
        throw error;
    }
}

// Browser-specific functions
function setupBrowserEventListeners() {
    if (typeof document === 'undefined') return;

    // Full pipeline test button
    const fullPipelineBtn = document.getElementById('fullPipelineBtn');
    if (fullPipelineBtn) {
        fullPipelineBtn.addEventListener('click', async () => {
            fullPipelineBtn.disabled = true;
            fullPipelineBtn.textContent = '🔄 Running...';
            
            try {
                await runFullPipelineTest();
            } catch (error) {
                // Error already logged in the function
            } finally {
                fullPipelineBtn.disabled = false;
                fullPipelineBtn.textContent = '🚀 Run Full Pipeline Test';
                updateProgressBar('Complete', 100, 'Test finished');
            }
        });
    }

    // Keygen only button
    const keygenOnlyBtn = document.getElementById('keygenOnlyBtn');
    if (keygenOnlyBtn) {
        keygenOnlyBtn.addEventListener('click', async () => {
            keygenOnlyBtn.disabled = true;
            keygenOnlyBtn.textContent = '🔄 Running...';
            
            try {
                await initializeWasm();
                await runKeyGeneration();
            } catch (error) {
                log(`Keygen test failed: ${error.message}`, "error");
            } finally {
                keygenOnlyBtn.disabled = false;
                keygenOnlyBtn.textContent = '🔑 Run Keygen Only';
            }
        });
    }

    // AuxGen only button
    const auxgenOnlyBtn = document.getElementById('auxgenOnlyBtn');
    if (auxgenOnlyBtn) {
        auxgenOnlyBtn.addEventListener('click', async () => {
            auxgenOnlyBtn.disabled = true;
            auxgenOnlyBtn.textContent = '🔄 Running...';
            
            try {
                await initializeWasm();
                log("Note: Running with mock incomplete key shares", "round");
                const mockShares = Array(3).fill(null).map((_, i) => ({ mock: true, index: i }));
                await runAuxGeneration(mockShares);
            } catch (error) {
                log(`AuxGen test failed: ${error.message}`, "error");
            } finally {
                auxgenOnlyBtn.disabled = false;
                auxgenOnlyBtn.textContent = '⚙️ Run AuxGen Only';
            }
        });
    }

    // Clear button
    const clearBtn = document.getElementById('clearBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            const output = document.getElementById('output');
            if (output) {
                output.textContent = 'Output cleared. Ready for new test...\n';
            }
            updateProgressBar('Ready', 0, 'Click a button to start');
        });
    }
}

// Initialize browser environment
function initializeBrowser() {
    if (typeof window !== 'undefined') {
        window.addEventListener('load', async () => {
            log("🔐 CGGMP21 Full Pipeline Test Ready");
            log("Initializing Web Worker for heavy computations...");
            
            // Initialize worker and set progress callback
            await workerManager.initialize();
            workerManager.setProgressCallback((progressData) => {
                const { phase, round, message, progress } = progressData;
                log(`${phase} ${round}: ${message}`, round ? "round" : "phase");
                updateProgressBar(phase, progress, message);
            });
            
            log("Click 'Run Full Pipeline Test' to start the complete protocol test");
            setupBrowserEventListeners();
        });
    }
}

// Auto-initialize if in browser environment
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeBrowser);
    } else {
        initializeBrowser();
    }
}

// For Node.js or direct script execution
if (typeof module !== 'undefined') {
    module.exports = { 
        runFullPipelineTest,
        runKeyGeneration,
        runAuxGeneration,
        runSigning,
        initializeWasm,
        log
    };
}

// Export individual test functions for debugging
export { 
    runKeyGeneration, 
    runAuxGeneration, 
    runSigning, 
    runFullPipelineTest,
    initializeWasm,
    log,
    setupBrowserEventListeners,
    workerManager
}; 
