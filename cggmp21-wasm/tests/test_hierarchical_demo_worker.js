// test_hierarchical_demo_worker.js - Web Worker for Demo
import init, {
    StatefulHierarchicalThresholdKeygenProtocol,
    StatefulAuxGenProtocol,
    StatefulSigningProtocol
} from '../pkg/cggmp21_wasm.js';

// Worker state
let wasmInitialized = false;

// Configuration
const MESSAGE_TO_SIGN = "48656c6c6f2c20576f726c6421"; // "Hello, World!" in hex

// Party configuration
const parties = [
    { i: 0, t: 3, ranks: [0, 0, 1, 1], n: 4, sid: "demo-session", reliable_broadcast_enforced: false, hd_enabled: false, ids: [1, 2, 3] },
    { i: 1, t: 3, ranks: [0, 0, 1, 1], n: 4, sid: "demo-session", reliable_broadcast_enforced: false, hd_enabled: false, ids: [0, 2, 3] },
    { i: 2, t: 3, ranks: [0, 0, 1, 1], n: 4, sid: "demo-session", reliable_broadcast_enforced: false, hd_enabled: false, ids: [0, 1, 3] },
    { i: 3, t: 3, ranks: [0, 0, 1, 1], n: 4, sid: "demo-session", reliable_broadcast_enforced: false, hd_enabled: false, ids: [0, 1, 2] }
];

// Progress reporting
function sendProgress(partyIdx, phase, round, message, progress = null) {
    postMessage({
        type: 'progress',
        data: { partyIdx, phase, round, message, progress }
    });
}
// Helper functions for message routing
const createRecipientMap = (items, partyConfig) => {
    const map = {};
    items.forEach((item, idx) => {
        map[idx] = items.filter((_, idx2) => partyConfig[idx].ids.includes(idx2));
    });
    return map;
};

const createUnicastMap = (unicastMessages, partyConfig) => {
    const map = {};
    
    // Initialize map with empty arrays for each party
    partyConfig.forEach((_, idx) => {
        map[idx] = [];
    });
    
    // Route unicast messages to recipients
    unicastMessages.forEach((partyMessages, senderIdx) => {
        if (Array.isArray(partyMessages)) {
            console.log(`Processing ${partyMessages.length} unicast messages from party ${senderIdx}`);
            partyMessages.forEach((unicastMsg, msgIdx) => {
                // Handle tuple format [recipient, message] from Rust
                const recipientIdx = Array.isArray(unicastMsg) ? unicastMsg[0] : unicastMsg.recipient;
                const message = Array.isArray(unicastMsg) ? unicastMsg[1] : unicastMsg.msg;
                
                console.log(`Message ${msgIdx}: sender=${senderIdx}, recipient=${recipientIdx}`);
                
                if (map[recipientIdx] !== undefined) {
                    map[recipientIdx].push(message);
                } else {
                    console.warn(`Invalid recipient index ${recipientIdx} for message from party ${senderIdx}`);
                }
            });
        }
    });
    
    // Log final routing results
    Object.keys(map).forEach(partyIdx => {
        console.log(`Party ${partyIdx} will receive ${map[partyIdx].length} sigma shares`);
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
            console.log(p2pMsg.recipient, p2pMsg.message);
            map[p2pMsg.recipient].push(p2pMsg.message);
        });
    });
    
    return map;
};


// Initialize WASM
async function initializeWasm() {
    if (!wasmInitialized) {
        await init();
        wasmInitialized = true;
        sendProgress(null, 'init', '', 'WASM module initialized');
    }
}

// Combined keygen and auxgen
async function runKeygenAuxgen() {
    console.log("[runKeygenAuxgen] START - Combined key generation and auxiliary setup");
    
    // Phase 1: Key Generation
    console.log("[runKeygenAuxgen] === PHASE 1: KEY GENERATION START ===");
    sendProgress(null, 'keygen', 'start', 'Starting Key Generation Phase', 5);

    // Initialize protocols
    console.log("[runKeygenAuxgen/Keygen] Initializing protocols for", parties.length, "parties");
    const keygenProtocols = [];
    for (let i = 0; i < parties.length; i++) {
        console.log(`[runKeygenAuxgen/Keygen] Initializing party ${i} with config:`, {
            index: parties[i].i,
            threshold: parties[i].t,
            rank: parties[i].ranks[i],
            sid: parties[i].sid
        });
        sendProgress(i, 'keygen', 'init', 'Initializing protocol...');
        try {
            const protocol = new StatefulHierarchicalThresholdKeygenProtocol(parties[i]);
            keygenProtocols.push(protocol);
            console.log(`[runKeygenAuxgen/Keygen] Party ${i} protocol initialized successfully`);
            sendProgress(i, 'keygen', 'init', 'Protocol initialized');
        } catch (error) {
            console.error(`[runKeygenAuxgen/Keygen] Failed to initialize party ${i}:`, error);
            throw error;
        }
    }
    console.log("[runKeygenAuxgen/Keygen] All protocols initialized");

    // Round 1: Commitments
    sendProgress(null, 'keygen', 'round1', 'Generating commitments...', 15);
    const commitments = await Promise.all(
        keygenProtocols.map(async (protocol, idx) => {
            sendProgress(idx, 'keygen', 'round1', 'Generating commitment...');
            const commitment = protocol.round1_generate_commitment();
            sendProgress(idx, 'keygen', 'round1', 'Commitment generated');
            return commitment;
        })
    );

    const commitmentsMap = createRecipientMap(commitments, parties);
    await Promise.all(
        keygenProtocols.map(async (protocol, idx) => {
            protocol.set_round1_commitments({
                commitments: commitmentsMap[idx],
                ids: parties[idx].ids
            });
            sendProgress(idx, 'keygen', 'round1', `Received ${commitmentsMap[idx].length} commitments`);
        })
    );

    // Round 2: Decommitments and shares
    sendProgress(null, 'keygen', 'round2', 'Generating decommitments and shares...', 30);
    const decommitments = await Promise.all(
        keygenProtocols.map(async (protocol, idx) => {
            sendProgress(idx, 'keygen', 'round2', 'Generating decommitment...');
            return protocol.round2_get_decommitment();
        })
    );

    const unicastMessages = await Promise.all(
        keygenProtocols.map(async (protocol, idx) => {
            sendProgress(idx, 'keygen', 'round2', 'Generating secret shares...');
            return protocol.round2_get_unicast_messages();
        })
    );

    const decommitmentsMap = createRecipientMap(decommitments, parties);
    const sigmasMap = createUnicastMap(unicastMessages, parties);

    await Promise.all(
        keygenProtocols.map(async (protocol, idx) => {
            protocol.set_round2_decommitments({
                decommitments: decommitmentsMap[idx],
                ids: parties[idx].ids
            });
            protocol.set_round2_sigmas({
                sigmas: sigmasMap[idx],
                ids: parties[idx].ids
            });
            sendProgress(idx, 'keygen', 'round2', 'Validating round 2 data...');
            protocol.validate_round2_and_prepare_round3();
            sendProgress(idx, 'keygen', 'round2', 'Round 2 validation complete');
        })
    );

    // Round 3: Schnorr proofs
    sendProgress(null, 'keygen', 'round3', 'Generating Schnorr proofs...', 45);
    const schnorrProofs = await Promise.all(
        keygenProtocols.map(async (protocol, idx) => {
            sendProgress(idx, 'keygen', 'round3', 'Generating Schnorr proof...');
            const proof = protocol.round3_generate_proof();
            sendProgress(idx, 'keygen', 'round3', 'Schnorr proof generated');
            return proof;
        })
    );

    const proofsMap = createRecipientMap(schnorrProofs, parties);
    await Promise.all(
        keygenProtocols.map(async (protocol, idx) => {
            protocol.set_round3_schnorr_proofs({
                sch_proof: proofsMap[idx],
                ids: parties[idx].ids
            });
            sendProgress(idx, 'keygen', 'round3', 'Schnorr proofs verified');
        })
    );

    // Finalize key generation
    sendProgress(null, 'keygen', 'final', 'Finalizing key generation...', 60);
    const incompleteKeyShares = await Promise.all(
        keygenProtocols.map(async (protocol, idx) => {
            sendProgress(idx, 'keygen', 'final', 'Generating key share...');
            const keyShare = protocol.finalize_key_generation();
            sendProgress(idx, 'keygen', 'final', `Key share generated (rank ${parties[idx].ranks[idx]})`);
            return keyShare;
        })
    );

    sendProgress(null, 'keygen', 'complete', 'Key generation completed!', 65);

    // Phase 2: Auxiliary Generation
    sendProgress(null, 'auxgen', 'start', 'Starting Auxiliary Generation Phase', 65);

    const auxGenProtocols = await Promise.all(
        parties.map(async (party, idx) => {
            sendProgress(idx, 'auxgen', 'init', 'Initializing auxiliary protocol...');
            const protocol = await new StatefulAuxGenProtocol({
                ...party,
                sid: party.sid + "-auxgen",
                compute_multiexp_table: false,
                compute_crt: false
            });
            sendProgress(idx, 'auxgen', 'init', 'Auxiliary protocol initialized');
            return protocol;
        })
    );

    // Aux Round 1
    sendProgress(null, 'auxgen', 'round1', 'Generating auxiliary commitments...', 75);
    const auxCommitments = await Promise.all(
        auxGenProtocols.map(async (protocol, idx) => {
            sendProgress(idx, 'auxgen', 'round1', 'Generating auxiliary commitment...');
            return protocol.round1_generate_commitment();
        })
    );

    const auxCommitmentsMap = createRecipientMap(auxCommitments, parties);
    await Promise.all(
        auxGenProtocols.map(async (protocol, idx) => {
            protocol.set_round1_commitments({
                commitments: auxCommitmentsMap[idx],
                ids: parties[idx].ids
            });
            sendProgress(idx, 'auxgen', 'round1', 'Auxiliary commitments set');
        })
    );

    // Aux Round 2
    sendProgress(null, 'auxgen', 'round2', 'Processing auxiliary decommitments...', 85);
    const auxDecommitments = await Promise.all(
        auxGenProtocols.map(async (protocol, idx) => {
            sendProgress(idx, 'auxgen', 'round2', 'Getting decommitment...');
            return protocol.round2_get_decommitment();
        })
    );

    const auxDecommitmentsMap = createRecipientMap(auxDecommitments, parties);
    await Promise.all(
        auxGenProtocols.map(async (protocol, idx) => {
            protocol.set_round2_decommitments({
                decommitments: auxDecommitmentsMap[idx],
                ids: parties[idx].ids
            });
            protocol.validate_round2_decommitments();
            sendProgress(idx, 'auxgen', 'round2', 'Decommitments validated');
        })
    );

    // Aux Round 3
    sendProgress(null, 'auxgen', 'round3', 'Finalizing auxiliary information...', 90);
    const round3Messages = await Promise.all(
        auxGenProtocols.map(async (protocol, idx) => {
            sendProgress(idx, 'auxgen', 'round3', 'Creating auxiliary messages...');
            return protocol.round3_create_messages();
        })
    );

    await Promise.all(
        auxGenProtocols.map(async (protocol, idx) => {
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
            sendProgress(idx, 'auxgen', 'round3', 'Messages processed');
        })
    );

    const auxInfos = await Promise.all(
        auxGenProtocols.map(async (protocol, idx) => {
            const auxInfo = protocol.finalize();
            sendProgress(idx, 'auxgen', 'final', 'Auxiliary information generated');
            return auxInfo;
        })
    );

    // Create complete key shares
    const completeKeyShares = incompleteKeyShares.map((incompleteShare, idx) => {
        return {
            core: incompleteShare,
            aux: auxInfos[idx],
            party_index: idx,
            rank: parties[idx].ranks[idx]
        };
    });

    sendProgress(null, 'auxgen', 'complete', 'Setup complete! Ready for signing.', 100);

    return { completeKeyShares };
}

// Signing with selected parties
async function runSigning(signers, keyShares) {
    try {
        console.log("[runSigning] START - Input signers:", signers);
        console.log("[runSigning] keyShares available:", keyShares ? keyShares.length : 'null');
        
        // Override for testing - remove this line after debugging
        console.log("[runSigning] Override signers to:", signers);

        const startTime = performance.now();

        sendProgress(null, 'signing', 'start', `Starting signing with parties [${signers.join(', ')}]`, 10);

        // Validate signing set
        console.log("[runSigning] Validating signing set...");
        const signerRanks = signers.map(idx => {
            const rank = parties[idx].ranks[idx];
            console.log(`[runSigning] Party ${idx} has rank ${rank}`);
            return rank;
        }).sort((a, b) => a - b);
        
        console.log("[runSigning] Sorted signer ranks:", signerRanks);
        const isValidSigningSet = signerRanks.every((rank, idx) => {
            const isValid = rank <= idx;
            console.log(`[runSigning] Rank validation: rank[${idx}]=${rank} <= ${idx} ? ${isValid}`);
            return isValid;
        });

        if (!isValidSigningSet) {
            console.error("[runSigning] Invalid signing set detected!");
            throw new Error(`Invalid signing set: ranks [${signerRanks.join(', ')}] violate hierarchical constraints`);
        }

        console.log("[runSigning] Signing set is valid!");
        sendProgress(null, 'signing', 'validate', `Valid signing set with ranks [${signerRanks.join(', ')}]`, 15);

        // Get key shares for signers
        console.log("[runSigning] Getting key shares for signers...");
        const signingKeyShares = signers.map(idx => {
            const keyShare = keyShares[idx];
            console.log(`[runSigning] KeyShare for party ${idx}:`, {
                hasCore: keyShare?.core ? true : false,
                hasAux: keyShare?.aux ? true : false,
                partyIndex: keyShare?.party_index,
                rank: keyShare?.rank
            });
            return keyShare;
        });

        // Create signing protocols
        console.log("[runSigning] Creating signing protocols...");
        
        // IMPORTANT: For signing, we need LOCAL indices [0, 1, 2, ...] for the signing group
        // regardless of which global parties are selected
        const localSigningIndices = Array.from({length: signers.length}, (_, i) => i);
        console.log("[runSigning] Local signing indices:", localSigningIndices);
        
        const signingProtocols = signers.map((globalIdx, localIdx) => {
            console.log(`[runSigning] Creating protocol for party ${globalIdx} (local index ${localIdx})...`);
            sendProgress(globalIdx, 'signing', 'init', 'Initializing signing protocol...');

            const protocolConfig = {
                i: localIdx,
                signing_parties: localSigningIndices, // Use LOCAL indices [0, 1, 2, ...]
                sid: parties[globalIdx].sid + "-signing",
                reliable_broadcast_enforced: false,
                message_hex: MESSAGE_TO_SIGN,
                enable_precomputable: false
            };
            
            console.log(`[runSigning] Protocol config for party ${globalIdx}:`, protocolConfig);
            
            try {
                const protocol = new StatefulSigningProtocol(protocolConfig, signingKeyShares[localIdx]);
                console.log(`[runSigning] Protocol created successfully for party ${globalIdx}`);
                sendProgress(globalIdx, 'signing', 'init', 'Signing protocol ready');
                return protocol;
            } catch (error) {
                console.error(`[runSigning] Failed to create protocol for party ${globalIdx}:`, error);
                throw error;
            }
        });

        console.log("[runSigning] All signing protocols created:", signingProtocols.length);

        // Round 1a
        console.log("[runSigning] === ROUND 1A START ===");
        sendProgress(null, 'signing', 'round1a', 'Generating broadcast messages...', 25);
        const round1aMessages = await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const globalIdx = signers[localIdx];
                console.log(`[runSigning/Round1a] Party ${globalIdx} generating message...`);
                sendProgress(globalIdx, 'signing', 'round1a', 'Generating round 1a message...');
                try {
                    const message = await protocol.round1a_generate_message();
                    console.log(`[runSigning/Round1a] Party ${globalIdx} message generated successfully`);
                    return message;
                } catch (error) {
                    console.error(`[runSigning/Round1a] Party ${globalIdx} failed:`, error);
                    throw error;
                }
            })
        );
        console.log(`[runSigning/Round1a] All messages generated: ${round1aMessages.length}`);

        await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const otherMessages = round1aMessages.filter((_, msgIdx) => msgIdx !== localIdx);
                // Use local indices for the IDs (exclude self)
                const otherLocalIds = localSigningIndices.filter(idx => idx !== localIdx);
                console.log(`[runSigning/Round1a] Party ${signers[localIdx]} (local ${localIdx}) setting ${otherMessages.length} messages from local indices:`, otherLocalIds);
                try {
                    protocol.set_round1a_messages({
                        messages: otherMessages,
                        ids: otherLocalIds
                    });
                    console.log(`[runSigning/Round1a] Party ${signers[localIdx]} messages set successfully`);
                } catch (error) {
                    console.error(`[runSigning/Round1a] Party ${signers[localIdx]} failed to set messages:`, error);
                    throw error;
                }
            })
        );
        console.log("[runSigning] === ROUND 1A COMPLETE ===");

        // Round 1b
        console.log("[runSigning] === ROUND 1B START ===");
        sendProgress(null, 'signing', 'round1b', 'Generating P2P messages...', 40);
        const round1bMessages = await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const globalIdx = signers[localIdx];
                console.log(`[runSigning/Round1b] Party ${globalIdx} generating P2P messages...`);
                sendProgress(globalIdx, 'signing', 'round1b', 'Generating round 1b messages...');
                try {
                    const messages = await protocol.round1b_generate_messages();
                    console.log(`[runSigning/Round1b] Party ${globalIdx} generated ${messages.length} P2P messages`);
                    return messages;
                } catch (error) {
                    console.error(`[runSigning/Round1b] Party ${globalIdx} failed:`, error);
                    throw error;
                }
            })
        );
        console.log(`[runSigning/Round1b] All P2P messages generated`);

        console.log("[runSigning/Round1b] Creating P2P map...");
        const round1bMap = createP2PMap(round1bMessages, localSigningIndices);
        console.log("[runSigning/Round1b] P2P map created:", Object.keys(round1bMap).map(k => `Local ${k}: ${round1bMap[k].length} messages`));
        
        await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const globalIdx = signers[localIdx];
                const messages = round1bMap[localIdx];
                const otherLocalIds = localSigningIndices.filter(idx => idx !== localIdx);
                console.log(`[runSigning/Round1b] Party ${globalIdx} (local ${localIdx}) setting ${messages.length} messages from local indices:`, otherLocalIds);
                
                try {
                    protocol.set_round1b_messages({
                        messages: messages,
                        ids: otherLocalIds
                    });
                    console.log(`[runSigning/Round1b] Party ${globalIdx} messages set, validating proofs...`);
                    protocol.validate_round1b_proofs();
                    console.log(`[runSigning/Round1b] Party ${globalIdx} proofs validated successfully`);
                    sendProgress(globalIdx, 'signing', 'round1b', 'Round 1b proofs validated');
                } catch (error) {
                    console.error(`[runSigning/Round1b] Party ${globalIdx} validation failed:`, error);
                    throw error;
                }
            })
        );
        console.log("[runSigning] === ROUND 1B COMPLETE ===");

        // Round 2
        console.log("[runSigning] === ROUND 2 START ===");
        sendProgress(null, 'signing', 'round2', 'Generating round 2 messages...', 55);
        const round2Messages = await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const globalIdx = signers[localIdx];
                console.log(`[runSigning/Round2] Party ${globalIdx} generating messages...`);
                sendProgress(globalIdx, 'signing', 'round2', 'Generating round 2 messages...');
                try {
                    const messages = await protocol.round2_generate_messages();
                    console.log(`[runSigning/Round2] Party ${globalIdx} generated ${messages.length} messages`);
                    return messages;
                } catch (error) {
                    console.error(`[runSigning/Round2] Party ${globalIdx} failed:`, error);
                    throw error;
                }
            })
        );
        console.log(`[runSigning/Round2] All messages generated`);

        console.log("[runSigning/Round2] Creating P2P map...");
        const round2Map = createP2PMap(round2Messages, localSigningIndices);
        console.log("[runSigning/Round2] P2P map created:", Object.keys(round2Map).map(k => `Local ${k}: ${round2Map[k].length} messages`));
        
        await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const globalIdx = signers[localIdx];
                const messages = round2Map[localIdx];
                const otherLocalIds = localSigningIndices.filter(idx => idx !== localIdx);
                console.log(`[runSigning/Round2] Party ${globalIdx} (local ${localIdx}) setting ${messages.length} messages`);
                
                try {
                    protocol.set_round2_messages({
                        messages: messages,
                        ids: otherLocalIds
                    });
                    console.log(`[runSigning/Round2] Party ${globalIdx} messages set successfully`);
                } catch (error) {
                    console.error(`[runSigning/Round2] Party ${globalIdx} failed to set messages:`, error);
                    throw error;
                }
            })
        );
        console.log("[runSigning] === ROUND 2 COMPLETE ===");

        // Round 3
        console.log("[runSigning] === ROUND 3 START ===");
        sendProgress(null, 'signing', 'round3', 'Generating round 3 messages...', 70);
        const round3Messages = await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const globalIdx = signers[localIdx];
                console.log(`[runSigning/Round3] Party ${globalIdx} generating messages...`);
                sendProgress(globalIdx, 'signing', 'round3', 'Generating round 3 messages...');
                try {
                    const messages = await protocol.round3_generate_messages();
                    console.log(`[runSigning/Round3] Party ${globalIdx} generated ${messages.length} messages`);
                    return messages;
                } catch (error) {
                    console.error(`[runSigning/Round3] Party ${globalIdx} failed:`, error);
                    throw error;
                }
            })
        );
        console.log(`[runSigning/Round3] All messages generated`);

        console.log("[runSigning/Round3] Creating P2P map...");
        const round3Map = createP2PMap(round3Messages, localSigningIndices);
        console.log("[runSigning/Round3] P2P map created:", Object.keys(round3Map).map(k => `Local ${k}: ${round3Map[k].length} messages`));
        
        await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const globalIdx = signers[localIdx];
                const messages = round3Map[localIdx];
                const otherLocalIds = localSigningIndices.filter(idx => idx !== localIdx);
                console.log(`[runSigning/Round3] Party ${globalIdx} (local ${localIdx}) setting ${messages.length} messages`);
                
                try {
                    protocol.set_round3_messages({
                        messages: messages,
                        ids: otherLocalIds
                    });
                    console.log(`[runSigning/Round3] Party ${globalIdx} messages set successfully`);
                } catch (error) {
                    console.error(`[runSigning/Round3] Party ${globalIdx} failed to set messages:`, error);
                    throw error;
                }
            })
        );
        console.log("[runSigning] === ROUND 3 COMPLETE ===");

        // Generate presignatures
        console.log("[runSigning] === PRESIGNATURE GENERATION START ===");
        sendProgress(null, 'signing', 'presignature', 'Generating presignatures...', 80);
        const presignatures = await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const globalIdx = signers[localIdx];
                console.log(`[runSigning/Presignature] Party ${globalIdx} generating presignature...`);
                sendProgress(globalIdx, 'signing', 'presignature', 'Generating presignature...');
                try {
                    const presignature = await protocol.generate_presignature();
                    console.log(`[runSigning/Presignature] Party ${globalIdx} presignature generated successfully`);
                    return presignature;
                } catch (error) {
                    console.error(`[runSigning/Presignature] Party ${globalIdx} failed:`, error);
                    throw error;
                }
            })
        );
        console.log(`[runSigning/Presignature] All presignatures generated: ${presignatures.length}`);
        console.log("[runSigning] === PRESIGNATURE GENERATION COMPLETE ===");

        // Round 4
        console.log("[runSigning] === ROUND 4 START ===");
        sendProgress(null, 'signing', 'round4', 'Generating partial signatures...', 90);
        const round4Messages = await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const globalIdx = signers[localIdx];
                console.log(`[runSigning/Round4] Party ${globalIdx} generating partial signature...`);
                sendProgress(globalIdx, 'signing', 'round4', 'Generating partial signature...');
                try {
                    const message = await protocol.round4_generate_message();
                    console.log(`[runSigning/Round4] Party ${globalIdx} partial signature generated:`, message ? "success" : "null");
                    return message;
                } catch (error) {
                    console.error(`[runSigning/Round4] Party ${globalIdx} failed:`, error);
                    throw error;
                }
            })
        );
        console.log(`[runSigning/Round4] All partial signatures generated`);

        console.log("[runSigning/Round4] Creating recipient map...");
        const round4Map = createRecipientMap(
            round4Messages.map((msg, idx) => {
                const result = (msg !== undefined && msg !== null) ? msg : {};
                console.log(`[runSigning/Round4] Message from party ${signers[idx]}:`, msg ? "has content" : "empty");
                return result;
            }),
            // Create config for local indices
            localSigningIndices.map((localIdx) => ({ 
                ids: localSigningIndices.filter(idx => idx !== localIdx) 
            }))
        );
        console.log("[runSigning/Round4] Recipient map created");

        await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const globalIdx = signers[localIdx];
                const messages = round4Map[localIdx];
                
                if (messages && messages.length > 0) {
                    const otherLocalIds = localSigningIndices.filter(idx => idx !== localIdx);
                    console.log(`[runSigning/Round4] Party ${globalIdx} (local ${localIdx}) setting ${messages.length} round 4 messages`);
                    try {
                        protocol.set_round4_messages({
                            messages: messages,
                            ids: otherLocalIds
                        });
                        console.log(`[runSigning/Round4] Party ${globalIdx} messages set successfully`);
                    } catch (error) {
                        console.error(`[runSigning/Round4] Party ${globalIdx} failed to set messages:`, error);
                        throw error;
                    }
                } else {
                    console.log(`[runSigning/Round4] Party ${globalIdx} has no messages to set`);
                }
            })
        );
        console.log("[runSigning] === ROUND 4 COMPLETE ===");

        // Generate final signatures
        console.log("[runSigning] === FINAL SIGNATURE GENERATION START ===");
        sendProgress(null, 'signing', 'final', 'Generating final signatures...', 95);
        const signatures = await Promise.all(
            signingProtocols.map(async (protocol, localIdx) => {
                const globalIdx = signers[localIdx];
                const round4Msg = round4Messages[localIdx];
                console.log(`[runSigning/Final] Party ${globalIdx} round4 message:`, round4Msg ? "available" : "null");
                
                if (round4Msg !== undefined && round4Msg !== null) {
                    console.log(`[runSigning/Final] Party ${globalIdx} generating final signature...`);
                    sendProgress(globalIdx, 'signing', 'final', 'Generating final signature...');
                    try {
                        const sig = protocol.generate_signature(round4Msg);
                        console.log(`[runSigning/Final] Party ${globalIdx} signature generated successfully`);
                        sendProgress(globalIdx, 'signing', 'final', 'Signature generated!');
                        return sig;
                    } catch (error) {
                        console.error(`[runSigning/Final] Party ${globalIdx} failed to generate signature:`, error);
                        throw error;
                    }
                } else {
                    console.log(`[runSigning/Final] Party ${globalIdx} skipping - no round 4 message`);
                    return null;
                }
            })
        );
        console.log(`[runSigning/Final] Signatures generated:`, signatures.map((s, i) => `Party ${signers[i]}: ${s ? "valid" : "null"}`));

        const validSignatures = signatures.filter(sig => sig !== null);
        console.log(`[runSigning/Final] Valid signatures count: ${validSignatures.length}`);
        console.log("[runSigning] === FINAL SIGNATURE GENERATION COMPLETE ===");

        // Verify signature
        console.log("[runSigning] === SIGNATURE VERIFICATION START ===");
        sendProgress(null, 'signing', 'verify', 'Verifying signature...', 98);
        
        if (validSignatures.length > 0) {
            console.log("[runSigning/Verify] Getting public key from keyshare...");
            const publicKeyHex = StatefulSigningProtocol.get_public_key_from_keyshare(keyShares[0]);
            console.log("[runSigning/Verify] Public key:", publicKeyHex);
            
            const signature = validSignatures[0];
            console.log("[runSigning/Verify] Using first valid signature for verification");
            console.log("[runSigning/Verify] Message to verify:", MESSAGE_TO_SIGN);
            
            try {
                const isValid = StatefulSigningProtocol.verify_signature(signature, publicKeyHex, MESSAGE_TO_SIGN);
                console.log(`[runSigning/Verify] Verification result: ${isValid ? "VALID" : "INVALID"}`);
                
                const endTime = performance.now();
                const signingTime = endTime - startTime;
                console.log(`[runSigning/Verify] Total signing time: ${signingTime}ms`);

                sendProgress(null, 'signing', 'complete', `Signature ${isValid ? 'verified' : 'invalid'}!`, 100);
                console.log("[runSigning] === SIGNATURE VERIFICATION COMPLETE ===");
                
                console.log("[runSigning] SUCCESS - Returning results");
                return {
                    signature,
                    isValid,
                    signingTime,
                    signers
                };
            } catch (error) {
                console.error("[runSigning/Verify] Verification failed:", error);
                throw error;
            }
        } else {
            console.error("[runSigning/Verify] No valid signatures to verify!");
            throw new Error("No valid signatures generated");
        }
    } catch (error) {
        console.error("[runSigning] CRITICAL ERROR:", error);
        console.error("[runSigning] Error stack:", error.stack);
        console.error("[runSigning] Error details:", JSON.stringify(error, null, 2));
        throw error;
    }
}

// Handle messages from main thread
self.onmessage = async function (e) {
    const { type, data, messageId } = e.data;
    console.log(`[Worker] Message received: type=${type}, messageId=${messageId}, hasData=${!!data}`);

    try {
        switch (type) {
            case 'init':
                console.log("[Worker] Initializing WASM...");
                await initializeWasm();
                console.log("[Worker] WASM initialized successfully");
                postMessage({ type: 'init_complete', messageId });
                break;

            case 'run_keygen_auxgen':
                console.log("[Worker] Starting keygen + auxgen process...");
                const keygenResult = await runKeygenAuxgen();
                console.log("[Worker] Keygen + auxgen complete, sending results");
                postMessage({
                    type: 'keygen_auxgen_complete',
                    data: keygenResult,
                    messageId
                });
                break;

            case 'run_signing':
                console.log("[Worker] Starting signing process...");
                console.log("[Worker] Signers:", data?.signers);
                console.log("[Worker] KeyShares available:", data?.keyShares ? data.keyShares.length : 'null');
                const signingResult = await runSigning(data.signers, data.keyShares);
                console.log("[Worker] Signing complete, sending results");
                postMessage({
                    type: 'signing_complete',
                    data: signingResult,
                    messageId
                });
                break;

            default:
                console.error(`[Worker] Unknown message type: ${type}`);
                throw new Error(`Unknown message type: ${type}`);
        }
    } catch (error) {
        console.error("[Worker] Error occurred:", error);
        console.error("[Worker] Error stack:", error.stack);
        postMessage({
            type: 'error',
            data: {
                message: error.message,
                stack: error.stack
            },
            messageId
        });
    }
};
