// Web Worker for CGGMP21 Protocol Operations
import init, { 
    StatefulKeygenProtocol, 
    StatefulAuxGenProtocol,
    StatefulSigningProtocol 
} from '../pkg/cggmp21_wasm.js';

// Worker state
let wasmInitialized = false;
let currentProtocol = null;
let protocolConfig = null;
let receivedMessages = new Map();
let currentPhase = null;
let currentRound = 0;

// Helper functions from the original test file
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
        if (Array.isArray(partyMessages)) {
            partyMessages.forEach(p2pMsg => {
                if (p2pMsg && p2pMsg.recipient !== undefined && p2pMsg.message !== undefined) {
                    map[p2pMsg.recipient].push(p2pMsg.message);
                }
            });
        }
    });
    
    return map;
};

// Logging function that sends messages back to main thread
function log(message, level = 'info') {
    postMessage({
        type: 'log',
        data: { message, level }
    });
}

// Progress reporting function
function updateProgress(percentage, message) {
    postMessage({
        type: 'progress',
        data: { percentage, message }
    });
}

// Send protocol message to other parties via main thread
function sendProtocolMessage(phase, round, message) {
    postMessage({
        type: 'round_message',
        data: { phase, round, message }
    });
}

// Initialize WASM in worker
async function initializeWasm() {
    if (!wasmInitialized) {
        try {
            await init();
            wasmInitialized = true;
            log('WASM initialized in worker', 'success');
            return true;
        } catch (error) {
            log(`Failed to initialize WASM in worker: ${error.message}`, 'error');
            return false;
        }
    }
    return true;
}

// Key Generation Implementation
async function runKeyGeneration(config) {
    log('Starting Key Generation Phase in worker', 'info');
    currentPhase = 'keygen';
    protocolConfig = config;
    
    const parties = [
        {
            i: 0,
            t: config.threshold,
            n: config.totalParties,
            sid: config.sessionId,
            reliable_broadcast_enforced: false,
            ids: [1, 2]
        },
        {
            i: 1,
            t: config.threshold,
            n: config.totalParties,
            sid: config.sessionId,
            reliable_broadcast_enforced: false,
            ids: [0, 2]
        },
        {
            i: 2,
            t: config.threshold,
            n: config.totalParties,
            sid: config.sessionId,
            reliable_broadcast_enforced: false,
            ids: [0, 1]
        }
    ];

    try {
        const keygenProtocols = parties.map(party => 
            new StatefulKeygenProtocol(party)
        );
        
        const myProtocol = keygenProtocols[config.partyId];
        currentProtocol = myProtocol;
        
        updateProgress(15, 'Round 1: Generating commitments...');
        log('Round 1: Generating commitments...', 'info');
        
        // Round 1: Generate commitment
        const commitment = myProtocol.round1_generate_commitment();
        sendProtocolMessage('keygen', 1, commitment);
        
        // Wait for all commitments
        await waitForMessages('keygen', 1, config.totalParties - 1);
        
        updateProgress(30, 'Round 2: Broadcasting decommitments...');
        log('Round 2: Broadcasting decommitments and sending sigmas...', 'info');
        
        // Round 2: Broadcast decommitment and send sigmas
        const decommitment = myProtocol.round2_broad();
        const sigmasMsgs = myProtocol.round2_uni();
        
        sendProtocolMessage('keygen', 2, { decommitment, sigmasMsgs });
        
        // Wait for round 2 messages
        await waitForMessages('keygen', 2, config.totalParties - 1);
        
        updateProgress(50, 'Round 3: Processing messages...');
        log('Round 3: Generating Schnorr proofs...', 'info');
        
        // Process received messages for round 3
        const round1Messages = receivedMessages.get('keygen-1') || [];
        const round2Messages = receivedMessages.get('keygen-2') || [];
        
        const commitments = [commitment, ...round1Messages.map(m => m.data)];
        const commitmentsMap = createRecipientMap(commitments, parties);
        
        const decommitments = [decommitment, ...round2Messages.map(m => m.data.decommitment)];
        const decommitmentsMap = createRecipientMap(decommitments, parties);
        
        // Collect sigmas
        const allSigmas = [sigmasMsgs];
        round2Messages.forEach(msg => {
            if (msg.data.sigmasMsgs) {
                allSigmas.push(msg.data.sigmasMsgs);
            }
        });
        
        const sigmasMap = {};
        allSigmas.forEach(msgs => {
            msgs.forEach(msg => {
                const recipient = msg.recipient.OneParty;
                if (!sigmasMap[recipient]) {
                    sigmasMap[recipient] = [];
                }
                sigmasMap[recipient].push(msg.msg.Round2Uni);
            });
        });
        
        // Round 3: Generate Schnorr proof
        const round3Msg = myProtocol.round3({
            commitments: commitmentsMap[config.partyId],
            ids: parties[config.partyId].ids
        }, {
            decommitments: decommitmentsMap[config.partyId],
            ids: parties[config.partyId].ids
        }, {
            sigmas: sigmasMap[config.partyId],
            ids: parties[config.partyId].ids
        });
        
        sendProtocolMessage('keygen', 3, round3Msg);
        
        // Wait for round 3 messages
        await waitForMessages('keygen', 3, config.totalParties - 1);
        
        updateProgress(80, 'Finalizing key generation...');
        log('Final: Generating incomplete key shares...', 'info');
        
        // Finalize key generation
        const round3Messages = receivedMessages.get('keygen-3') || [];
        const schProofs = [round3Msg, ...round3Messages.map(m => m.data)];
        const schProofMap = createRecipientMap(schProofs, parties);
        
        const incompleteKeyShare = myProtocol.round_key_share({
            commitments: commitmentsMap[config.partyId],
            ids: parties[config.partyId].ids
        }, {
            decommitments: decommitmentsMap[config.partyId],
            ids: parties[config.partyId].ids
        }, {
            sigmas: sigmasMap[config.partyId],
            ids: parties[config.partyId].ids
        }, {
            sch_proof: schProofMap[config.partyId],
            ids: parties[config.partyId].ids
        });
        
        log('Key generation completed successfully!', 'success');
        
        // Clear received messages for this phase
        clearPhaseMessages('keygen');
        
        postMessage({
            type: 'phase_complete',
            data: {
                phase: 'keygen',
                result: {
                    incompleteKeyShares: [incompleteKeyShare]
                }
            }
        });
        
    } catch (error) {
        log(`Key generation error: ${error.message}`, 'error');
        postMessage({
            type: 'error',
            data: { message: error.message, phase: 'keygen' }
        });
    }
}

// Auxiliary Generation Implementation
async function runAuxGeneration(config) {
    log('Starting Auxiliary Generation Phase in worker', 'info');
    currentPhase = 'auxgen';
    protocolConfig = config;
    
    const parties = [
        {
            i: 0,
            t: config.threshold,
            n: config.totalParties,
            sid: config.sessionId,
            reliable_broadcast_enforced: false,
            ids: [1, 2]
        },
        {
            i: 1,
            t: config.threshold,
            n: config.totalParties,
            sid: config.sessionId,
            reliable_broadcast_enforced: false,
            ids: [0, 2]
        },
        {
            i: 2,
            t: config.threshold,
            n: config.totalParties,
            sid: config.sessionId,
            reliable_broadcast_enforced: false,
            ids: [0, 1]
        }
    ];

    try {
        const auxGenProtocol = new StatefulAuxGenProtocol({
            ...parties[config.partyId],
            compute_multiexp_table: false,
            compute_crt: false
        });
        
        currentProtocol = auxGenProtocol;
        
        updateProgress(45, 'Round 1: Generating aux commitments...');
        log('Round 1: Generating commitments...', 'info');
        
        // Round 1: Generate commitment
        const commitment = auxGenProtocol.round1_generate_commitment();
        sendProtocolMessage('auxgen', 1, commitment);
        
        // Wait for all commitments
        await waitForMessages('auxgen', 1, config.totalParties - 1);
        
        // Process commitments
        const round1Messages = receivedMessages.get('auxgen-1') || [];
        const commitments = [commitment, ...round1Messages.map(m => m.data)];
        const commitmentsMap = createRecipientMap(commitments, parties);
        
        auxGenProtocol.set_round1_commitments({
            commitments: commitmentsMap[config.partyId],
            ids: parties[config.partyId].ids
        });
        
        updateProgress(55, 'Round 2: Getting decommitments...');
        log('Round 2: Getting decommitments...', 'info');
        
        // Round 2: Get decommitment
        const decommitment = auxGenProtocol.round2_get_decommitment();
        sendProtocolMessage('auxgen', 2, decommitment);
        
        // Wait for decommitments
        await waitForMessages('auxgen', 2, config.totalParties - 1);
        
        const round2Messages = receivedMessages.get('auxgen-2') || [];
        const decommitments = [decommitment, ...round2Messages.map(m => m.data)];
        const decommitmentsMap = createRecipientMap(decommitments, parties);
        
        auxGenProtocol.set_round2_decommitments({
            decommitments: decommitmentsMap[config.partyId],
            ids: parties[config.partyId].ids
        });
        
        auxGenProtocol.validate_round2_decommitments();
        
        updateProgress(65, 'Round 3: Creating messages...');
        log('Round 3: Creating messages...', 'info');
        
        // Round 3: Create messages
        const round3Messages = auxGenProtocol.round3_create_messages();
        sendProtocolMessage('auxgen', 3, round3Messages);
        
        // Wait for round 3 messages
        await waitForMessages('auxgen', 3, config.totalParties - 1);
        
        const round3MessagesReceived = receivedMessages.get('auxgen-3') || [];
        const round3Map = createP2PMap([round3Messages, ...round3MessagesReceived.map(m => m.data)], parties);
        
        auxGenProtocol.set_round3_messages({
            messages: round3Map[config.partyId],
            ids: parties[config.partyId].ids
        });
        
        updateProgress(75, 'Finalizing auxiliary info...');
        log('Final: Finalizing auxiliary info...', 'info');
        
        const auxInfo = auxGenProtocol.finalize();
        
        const completeKeyShare = {
            core: config.keyShares[0], // Use the incomplete key share from keygen
            aux: auxInfo,
            party_index: config.partyId
        };
        
        log('Auxiliary generation completed successfully!', 'success');
        
        // Clear received messages for this phase
        clearPhaseMessages('auxgen');
        
        postMessage({
            type: 'phase_complete',
            data: {
                phase: 'auxgen',
                result: {
                    completeKeyShares: [completeKeyShare]
                }
            }
        });
        
    } catch (error) {
        log(`Auxiliary generation error: ${error.message}`, 'error');
        postMessage({
            type: 'error',
            data: { message: error.message, phase: 'auxgen' }
        });
    }
}

// Signing Implementation
async function runSigning(config) {
    log('Starting Signing Phase in worker', 'info');
    currentPhase = 'signing';
    protocolConfig = config;
    
    try {
        const signingParties = config.signingParties || [0, 1];
        const isSigningParty = signingParties.includes(config.partyId);
        
        if (!isSigningParty) {
            log(`Party ${config.partyId} is not a signing party, skipping signing`, 'info');
            return;
        }
        
        const localIdx = signingParties.indexOf(config.partyId);
        const keyShare = config.keyShares[0]; // Use the complete key share
        
        const signingProtocol = new StatefulSigningProtocol({
            i: localIdx,
            signing_parties: signingParties,
            sid: config.sessionId,
            reliable_broadcast_enforced: false,
            message_hex: config.messageHex,
            enable_precomputable: true // Default to enabling precompute tables
        }, keyShare);
        
        currentProtocol = signingProtocol;
        
        updateProgress(75, 'Round 1a: Generating broadcast messages...');
        log('Round 1a: Generating broadcast messages...', 'info');
        
        // Round 1a: Generate broadcast message
        const round1aMessage = signingProtocol.round1a_generate_message();
        sendProtocolMessage('signing', 1, { type: '1a', message: round1aMessage });
        
        // Wait for round 1a messages
        await waitForMessages('signing', 1, signingParties.length - 1);
        
        const round1aMessages = receivedMessages.get('signing-1') || [];
        const round1aOtherMessages = round1aMessages
            .filter(m => m.data.type === '1a')
            .map(m => m.data.message);
        const round1aOtherIds = signingParties.filter(id => id !== config.partyId);
        
        signingProtocol.set_round1a_messages({
            messages: round1aOtherMessages,
            ids: round1aOtherIds
        });
        
        updateProgress(80, 'Round 1b: Generating P2P messages...');
        log('Round 1b: Generating P2P messages...', 'info');
        
        // Round 1b: Generate P2P messages
        const round1bMessages = signingProtocol.round1b_generate_messages();
        sendProtocolMessage('signing', 1, { type: '1b', messages: round1bMessages });
        
        // Wait for more round 1 messages (1b)
        await waitForMessages('signing', 1, signingParties.length - 1, 2); // Wait for both 1a and 1b
        
        const round1bOtherMessages = round1aMessages
            .filter(m => m.data.type === '1b')
            .map(m => m.data.messages);
        
        const round1bMap = createP2PMap(round1bOtherMessages, signingParties);
        
        signingProtocol.set_round1b_messages({
            messages: round1bMap[localIdx],
            ids: signingParties.filter(id => id !== config.partyId)
        });
        
        signingProtocol.validate_round1b_proofs();
        
        updateProgress(85, 'Round 2: Generating P2P messages...');
        log('Round 2: Generating P2P messages...', 'info');
        
        // Round 2: Generate P2P messages
        const round2Messages = signingProtocol.round2_generate_messages();
        sendProtocolMessage('signing', 2, round2Messages);
        
        // Wait for round 2 messages
        await waitForMessages('signing', 2, signingParties.length - 1);
        
        const round2MessagesReceived = receivedMessages.get('signing-2') || [];
        const round2Map = createP2PMap([round2Messages, ...round2MessagesReceived.map(m => m.data)], signingParties);
        
        signingProtocol.set_round2_messages({
            messages: round2Map[localIdx],
            ids: signingParties.filter(id => id !== config.partyId)
        });
        
        updateProgress(90, 'Round 3: Generating P2P messages...');
        log('Round 3: Generating P2P messages...', 'info');
        
        // Round 3: Generate P2P messages
        const round3Messages = signingProtocol.round3_generate_messages();
        sendProtocolMessage('signing', 3, round3Messages);
        
        // Wait for round 3 messages
        await waitForMessages('signing', 3, signingParties.length - 1);
        
        const round3MessagesReceived = receivedMessages.get('signing-3') || [];
        const round3Map = createP2PMap([round3Messages, ...round3MessagesReceived.map(m => m.data)], signingParties);
        
        signingProtocol.set_round3_messages({
            messages: round3Map[localIdx],
            ids: signingParties.filter(id => id !== config.partyId)
        });
        
        updateProgress(95, 'Generating presignatures...');
        log('Generating presignatures...', 'info');
        
        const presignature = signingProtocol.generate_presignature();
        
        log('Round 4: Generating partial signatures...', 'info');
        
        const round4Message = signingProtocol.round4_generate_message();
        
        if (round4Message !== undefined && round4Message !== null) {
            sendProtocolMessage('signing', 4, round4Message);
            
            // Wait for round 4 messages
            await waitForMessages('signing', 4, signingParties.length - 1);
            
            const round4MessagesReceived = receivedMessages.get('signing-4') || [];
            const round4Map = createRecipientMap(
                [round4Message, ...round4MessagesReceived.map(m => m.data)],
                signingParties.map((_, idx) => ({ ids: signingParties.filter((_, partyIdx) => partyIdx !== idx) }))
            );
            
            if (round4Map[localIdx] && round4Map[localIdx].length > 0) {
                signingProtocol.set_round4_messages({
                    messages: round4Map[localIdx],
                    ids: signingParties.filter(id => id !== config.partyId)
                });
            }
        }
        
        updateProgress(98, 'Finalizing signatures...');
        log('Final: Generating signatures...', 'info');
        
        const signature = signingProtocol.generate_signature(round4Message);
        
        // Verify signature
        const publicKey = StatefulSigningProtocol.get_public_key_from_keyshare(keyShare);
        const isValid = StatefulSigningProtocol.verify_signature(signature, publicKey, config.messageHex);
        
        log(`Signature verification: ${isValid ? 'VALID' : 'INVALID'}`, isValid ? 'success' : 'error');
        
        // Clear received messages for this phase
        clearPhaseMessages('signing');
        
        postMessage({
            type: 'phase_complete',
            data: {
                phase: 'signing',
                result: {
                    presignatures: [presignature],
                    signatures: [signature],
                    publicKey: publicKey,
                    verificationResults: [{
                        signatureIndex: 0,
                        isValid: isValid,
                        signature: signature
                    }]
                }
            }
        });
        
        log('Signing completed successfully!', 'success');
        
    } catch (error) {
        log(`Signing error: ${error.message}`, 'error');
        postMessage({
            type: 'error',
            data: { message: error.message, phase: 'signing' }
        });
    }
}

// Wait for messages from other parties
function waitForMessages(phase, round, expectedCount, multiplier = 1) {
    return new Promise((resolve, reject) => {
        const key = `${phase}-${round}`;
        const timeout = setTimeout(() => {
            reject(new Error(`Timeout waiting for ${phase} round ${round} messages`));
        }, 30000); // 30 second timeout
        
        const checkMessages = () => {
            const messages = receivedMessages.get(key) || [];
            if (messages.length >= expectedCount * multiplier) {
                clearTimeout(timeout);
                resolve(messages);
            } else {
                setTimeout(checkMessages, 100); // Check every 100ms
            }
        };
        
        checkMessages();
    });
}

// Clear messages for a specific phase
function clearPhaseMessages(phase) {
    const keysToDelete = [];
    for (const key of receivedMessages.keys()) {
        if (key.startsWith(phase + '-')) {
            keysToDelete.push(key);
        }
    }
    keysToDelete.forEach(key => receivedMessages.delete(key));
}

// Message handler for the worker
self.onmessage = async function(e) {
    const { type, config, phase, round, sender, data } = e.data;
    
    switch (type) {
        case 'start_keygen':
            if (await initializeWasm()) {
                await runKeyGeneration(config);
            }
            break;
            
        case 'start_auxgen':
            if (await initializeWasm()) {
                await runAuxGeneration(config);
            }
            break;
            
        case 'start_signing':
            if (await initializeWasm()) {
                await runSigning(config);
            }
            break;
            
        case 'protocol_message':
            // Store received protocol message
            const key = `${phase}-${round}`;
            if (!receivedMessages.has(key)) {
                receivedMessages.set(key, []);
            }
            receivedMessages.get(key).push({ sender, data });
            log(`Received ${phase} Round ${round} message from Party ${sender}`, 'info');
            break;
            
        default:
            log(`Unknown message type in worker: ${type}`, 'warning');
    }
};

// Worker ready signal
postMessage({ type: 'ready' }); 
