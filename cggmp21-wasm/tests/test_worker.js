// test_worker.js - Web Worker for heavy CGGMP21 computations
import init, {
    StatefulKeygenProtocol,
    StatefulAuxGenProtocol,
    StatefulSigningProtocol
} from '../pkg/cggmp21_wasm.js';

// Worker state
let wasmInitialized = false;

// Global state for precompute tables
let usePrecomputeTables = true;
let precomputeTablesCache = new Map();

// Test configuration for 2-of-3 threshold signing
const parties = [
    {
        i: 0, t: 2, n: 3,
        sid: "test-signing-session-123",
        reliable_broadcast_enforced: false,
        ids: [1, 2]
    },
    {
        i: 1, t: 2, n: 3,
        sid: "test-signing-session-123",
        reliable_broadcast_enforced: false,
        ids: [0, 2]
    },
    {
        i: 2, t: 2, n: 3,
        sid: "test-signing-session-123",
        reliable_broadcast_enforced: false,
        ids: [0, 1]
    }
];

const MESSAGE_TO_SIGN = "48656c6c6f2c20576f726c6421"; // "Hello, World!" in hex

// Helper functions for message routing
const createRecipientMap = (items, partyConfig) => {
    const map = {};
    items.forEach((item, idx) => {
        map[idx] = items.filter((_, idx2) => partyConfig[idx].ids.includes(idx2));
    });
    return map;
};

const createP2PMap = (p2pMessages, parties) => {
    const map = {};
    parties.forEach((_, idx) => {
        map[idx] = [];
    });
    p2pMessages.forEach((partyMessages, senderIdx) => {
        partyMessages.forEach(p2pMsg => {
            console.log(p2pMsg.recipient, p2pMsg.message);
            map[p2pMsg.recipient].push(p2pMsg.message);
        });
    });
    return map;
};

// Progress reporting helper
const sendProgress = (phase, round, message, progress = null) => {
    console.log("sendProgress", phase, round, message, progress);
    postMessage({
        type: 'progress',
        data: { phase, round, message, progress }
    });
};

// Helper functions for precompute table management
async function generatePrecomputeTables(signingProtocol, cacheKey) {
    if (!usePrecomputeTables) {
        return null;
    }
    
    // Check cache first
    if (precomputeTablesCache.has(cacheKey)) {
        sendProgress('precompute', 'cache', `Using cached precompute tables for ${cacheKey}`);
        return precomputeTablesCache.get(cacheKey);
    }
    
    sendProgress('precompute', 'generate', `Generating precompute tables for ${cacheKey}...`);
    const start = performance.now();
    
    try {
        const tables = signingProtocol.generate_precompute_tables();
        const end = performance.now();
        
        sendProgress('precompute', 'complete', `Generated precompute tables in ${(end - start).toFixed(2)}ms`);
        
        // Cache the tables
        precomputeTablesCache.set(cacheKey, tables);
        
        return tables;
    } catch (error) {
        sendProgress('precompute', 'error', `Failed to generate precompute tables: ${error.message}`);
        throw error;
    }
}

// Initialize WASM module
async function initializeWasm() {
    if (!wasmInitialized) {
        await init();
        wasmInitialized = true;
        sendProgress('init', '', 'WASM module initialized successfully');
    }
}

// Phase 1: Key Generation
async function runKeyGeneration() {
    sendProgress('keygen', 'start', 'Starting Key Generation Phase');

    const keygenProtocols = parties.map(party =>
        new StatefulKeygenProtocol({
            ...party,
            sid: party.sid + "-keygen"
        })
    );

    // Round 1: Generate commitments (parallelized)
    sendProgress('keygen', 'round1', 'Generating commitments...', 25);
    const commitments = await Promise.all(
        keygenProtocols.map(protocol =>
            Promise.resolve(protocol.round1_generate_commitment())
        )
    );

    // Round 2: Broadcast decommitments and send sigmas (parallelized)
    sendProgress('keygen', 'round2', 'Broadcasting decommitments and sending sigmas...', 50);
    const [decommitments, sigmasMsgs] = await Promise.all([
        Promise.all(keygenProtocols.map(protocol =>
            Promise.resolve(protocol.round2_broad())
        )),
        Promise.all(keygenProtocols.map(protocol =>
            Promise.resolve(protocol.round2_uni())
        ))
    ]);

    // Create sigma routing map
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

    // Round 3: Generate Schnorr proofs (parallelized)
    sendProgress('keygen', 'round3', 'Generating Schnorr proofs...', 75);
    const commitmentsMap = createRecipientMap(commitments, parties);
    const decommitmentsMap = createRecipientMap(decommitments, parties);

    const round3Msgs = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve(protocol.round3({
                commitments: commitmentsMap[idx],
                ids: parties[idx].ids
            }, {
                decommitments: decommitmentsMap[idx],
                ids: parties[idx].ids
            }, {
                sigmas: sigmasMap[idx],
                ids: parties[idx].ids
            }))
        )
    );

    // Final round: Generate incomplete key shares (parallelized)
    sendProgress('keygen', 'final', 'Generating incomplete key shares...', 90);
    const schProofMap = createRecipientMap(round3Msgs, parties);
    console.log("schProofMap", schProofMap);
    const incompleteKeyShares = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve(protocol.round_key_share({
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
            }))
        )
    );

    console.log("incompleteKeyShares", incompleteKeyShares);

    sendProgress('keygen', 'complete', `Key generation completed! Generated ${incompleteKeyShares.length} incomplete key shares`, 100);
    return incompleteKeyShares;
}

// Phase 2: Auxiliary Information Generation
async function runAuxGeneration(incompleteKeyShares) {
    sendProgress('auxgen', 'start', 'Starting Auxiliary Generation Phase');

    const auxGenProtocols = await Promise.all(
        parties.map(party =>
            Promise.resolve(new StatefulAuxGenProtocol({
                ...party,
                sid: party.sid + "-auxgen",
                compute_multiexp_table: false,
                compute_crt: false
            }))
        )
    );

    // Round 1: Generate commitments (parallelized)
    console.log("auxGenProtocols", auxGenProtocols);
    sendProgress('auxgen', 'round1', 'Generating commitments...', 25);
    const commitments = await Promise.all(
        auxGenProtocols.map(protocol =>
            Promise.resolve(protocol.round1_generate_commitment())
        )
    );

    console.log("commitments", commitments);

    const commitmentsMap = createRecipientMap(commitments, parties);
    await Promise.all(
        auxGenProtocols.map(async (protocol, idx) => {
            return Promise.resolve(protocol.set_round1_commitments({
                commitments: commitmentsMap[idx],
                ids: parties[idx].ids
            }));
        })
    );

    console.log("auxGenProtocols", auxGenProtocols);

    // Round 2: Get decommitments (parallelized)
    sendProgress('auxgen', 'round2', 'Getting decommitments...', 50);
    const decommitments = await Promise.all(
        auxGenProtocols.map(protocol =>
            Promise.resolve(protocol.round2_get_decommitment())
        )
    );

    console.log("decommitments", decommitments);

    const decommitmentsMap = createRecipientMap(decommitments, parties);
    await Promise.all(
        auxGenProtocols.map(async (protocol, idx) => {
            protocol.set_round2_decommitments({
                decommitments: decommitmentsMap[idx],
                ids: parties[idx].ids
            });
            console.log("validate_round2_decommitments", protocol.validate_round2_decommitments());
            return Promise.resolve();
        })
    );

    // Round 3: Create messages (parallelized)
    sendProgress('auxgen', 'round3', 'Creating messages...', 75);
    const round3Messages = await Promise.all(
        auxGenProtocols.map(protocol =>
            Promise.resolve(protocol.round3_create_messages())
        )
    );

    console.log("round3Messages", round3Messages);

    const setRound3Messages = async (protocols, round3Messages) => {
        console.log("Setting Round 3 messages for all parties");

        // Convert the message format - the round3Messages from round3_create_messages() 
        // appears to be in a different format than what set_round3_messages expects
        await Promise.all(
            protocols.map(async (protocol, idx) => {
                try {
                    // Collect messages intended for this party from all other parties
                    const messagesForParty = [];

                    round3Messages.forEach((msgs, senderIdx) => {
                        if (senderIdx !== idx && parties[idx].ids.includes(senderIdx)) {
                            // msgs should be an array of (recipient_id, message) pairs
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

                    await Promise.resolve(protocol.set_round3_messages({
                        messages: messagesForParty,
                        ids: parties[idx].ids
                    }));
                    console.log(`Party ${idx} set ${messagesForParty.length} round 3 messages`);
                } catch (error) {
                    console.error(`Party ${idx} failed setting round 3 messages:`, error);
                    throw error;
                }
            })
        );
    };

    // const round3Map = createP2PMap(round3Messages, parties);
    await setRound3Messages(auxGenProtocols, round3Messages);

    // Set round 3 messages and finalize (parallelized)
    sendProgress('auxgen', 'final', 'Finalizing auxiliary info...', 90);

    const auxInfos = await Promise.all(
        auxGenProtocols.map((protocol, idx) =>
            Promise.resolve(protocol.finalize())
        )
    );

    console.log(auxInfos);

    const completeKeyShares = incompleteKeyShares.map((incompleteShare, idx) => {
        return {
            core: incompleteShare,
            aux: auxInfos[idx],
            party_index: idx
        };
    });

    sendProgress('auxgen', 'complete', `Auxiliary generation completed! Generated ${completeKeyShares.length} complete key shares`, 100);
    return completeKeyShares;
}

// Phase 3: Signing
async function runSigning(completeKeyShares) {
    sendProgress('signing', 'start', 'Starting Signing Phase');
    sendProgress('signing', 'config', `Precompute tables: ${usePrecomputeTables ? 'ENABLED' : 'DISABLED'}`);

    const signingParties = [0, 1];
    const signingKeyShares = signingParties.map(idx => completeKeyShares[idx]);

    // Create a test protocol instance to generate precompute tables if needed
    let precomputeTables = null;
    if (usePrecomputeTables) {
        sendProgress('signing', 'precompute', 'Generating precompute tables for signing parties...');
        const testProtocol = new StatefulSigningProtocol({
            i: 0,
            signing_parties: [0, 1],
            sid: parties[0].sid + "-signing-precompute",
            reliable_broadcast_enforced: false,
            message_hex: MESSAGE_TO_SIGN
        }, signingKeyShares[0]);
        
        precomputeTables = await generatePrecomputeTables(testProtocol, "signing-2of3");
    }

    const signingProtocols = signingParties.map((globalIdx, localIdx) => {
        const protocol = new StatefulSigningProtocol({
            i: localIdx,
            signing_parties: [0, 1],
            sid: parties[globalIdx].sid + "-signing",
            reliable_broadcast_enforced: false,
            message_hex: MESSAGE_TO_SIGN,
            precompute_tables: precomputeTables
        }, signingKeyShares[localIdx]);
        
        // Set precompute tables if available
        if (precomputeTables && usePrecomputeTables) {
            try {
                protocol.set_cached_precompute_tables(precomputeTables);
                sendProgress('signing', 'setup', `Precompute tables set for party ${localIdx}`);
            } catch (error) {
                sendProgress('signing', 'error', `Failed to set precompute tables for party ${localIdx}: ${error.message}`);
            }
        }
        
        return protocol;
    });

    // Round 1a: Generate broadcast messages (parallelized)
    sendProgress('signing', 'round1a', 'Generating broadcast messages...', 15);
    const start1a = performance.now();
    const round1aMessages = await Promise.all(
        signingProtocols.map(protocol =>
            Promise.resolve(protocol.round1a_generate_message())
        )
    );
    const end1a = performance.now();
    sendProgress('signing', 'timing', `Round 1a completed in ${(end1a - start1a).toFixed(2)}ms`);

    await Promise.all(
        signingProtocols.map(async (protocol, idx) => {
            const otherMessages = round1aMessages.filter((_, msgIdx) => msgIdx !== idx);
            const otherIds = signingParties.filter((_, partyIdx) => partyIdx !== idx);
            return Promise.resolve(protocol.set_round1a_messages({
                messages: otherMessages,
                ids: otherIds
            }));
        })
    );

    // Round 1b: Generate P2P messages (parallelized)
    sendProgress('signing', 'round1b', 'Generating P2P messages...', 30);
    const round1bMessages = await Promise.all(
        signingProtocols.map(protocol =>
            Promise.resolve(protocol.round1b_generate_messages())
        )
    );

    const round1bMap = createP2PMap(round1bMessages, signingParties);
    await Promise.all(
        signingProtocols.map(async (protocol, idx) => {
            protocol.set_round1b_messages({
                messages: round1bMap[idx],
                ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
            });
            protocol.validate_round1b_proofs();
            return Promise.resolve();
        })
    );

    // Round 2: Generate P2P messages (parallelized)
    sendProgress('signing', 'round2', 'Generating P2P messages...', 45);
    const start2 = performance.now();
    const round2Messages = await Promise.all(
        signingProtocols.map(protocol =>
            Promise.resolve(protocol.round2_generate_messages())
        )
    );
    const end2 = performance.now();
    sendProgress('signing', 'timing', `Round 2 completed in ${(end2 - start2).toFixed(2)}ms`);

    const round2Map = createP2PMap(round2Messages, signingParties);
    await Promise.all(
        signingProtocols.map(async (protocol, idx) => {
            return Promise.resolve(protocol.set_round2_messages({
                messages: round2Map[idx],
                ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
            }));
        })
    );

    // Round 3: Generate P2P messages (parallelized)
    sendProgress('signing', 'round3', 'Generating P2P messages...', 60);
    const round3Messages = await Promise.all(
        signingProtocols.map(protocol =>
            Promise.resolve(protocol.round3_generate_messages())
        )
    );

    const round3Map = createP2PMap(round3Messages, signingParties);
    await Promise.all(
        signingProtocols.map(async (protocol, idx) => {
            return Promise.resolve(protocol.set_round3_messages({
                messages: round3Map[idx],
                ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
            }));
        })
    );

    // Generate presignatures (parallelized)
    sendProgress('signing', 'presignature', 'Generating presignatures...', 75);
    const presignatures = await Promise.all(
        signingProtocols.map(protocol =>
            Promise.resolve(protocol.generate_presignature())
        )
    );

    // Round 4: Generate partial signatures (parallelized)
    sendProgress('signing', 'round4', 'Generating partial signatures...', 85);
    const round4Messages = await Promise.all(
        signingProtocols.map(protocol =>
            Promise.resolve(protocol.round4_generate_message())
        )
    );

    const round4Map = createRecipientMap(
        round4Messages.map(msg => (msg !== undefined && msg !== null) ? msg : {}),
        signingParties.map((_, idx) => ({ ids: signingParties.filter((_, partyIdx) => partyIdx !== idx) }))
    );

    await Promise.all(
        signingProtocols.map(async (protocol, idx) => {
            if (round4Map[idx] && round4Map[idx].length > 0) {
                return Promise.resolve(protocol.set_round4_messages({
                    messages: round4Map[idx],
                    ids: signingParties.filter((_, partyIdx) => partyIdx !== idx)
                }));
            }
            return Promise.resolve();
        })
    );

    // Generate final signatures (parallelized)
    sendProgress('signing', 'final', 'Generating signatures...', 95);
    const signatures = await Promise.all(
        signingProtocols.map((protocol, idx) => {
            const round4Msg = round4Messages[idx];
            if (round4Msg !== undefined && round4Msg !== null) {
                return Promise.resolve(protocol.generate_signature(round4Msg));
            }
            return Promise.resolve(null);
        })
    );

    const validSignatures = signatures.filter(sig => sig !== null);
    
    // Verify signatures (parallelized)
    sendProgress('signing', 'verification', 'Verifying signatures...', 98);
    const verificationResults = [];
    
    if (validSignatures.length > 0) {
        try {
            // Get public key from the first complete key share
            const publicKeyHex = StatefulSigningProtocol.get_public_key_from_keyshare(completeKeyShares[0]);
            
            const verificationPromises = validSignatures.map((signature, i) =>
                Promise.resolve(StatefulSigningProtocol.verify_signature(signature, publicKeyHex, MESSAGE_TO_SIGN))
                    .then(isValid => ({
                        signatureIndex: i,
                        isValid: isValid,
                        signature: signature
                    }))
            );
            
            const results = await Promise.all(verificationPromises);
            verificationResults.push(...results);
            
            results.forEach(result => {
                if (result.isValid) {
                    console.log(`✅ Signature ${result.signatureIndex} verification: VALID`);
                } else {
                    console.log(`❌ Signature ${result.signatureIndex} verification: INVALID`);
                }
            });
        } catch (error) {
            console.error("Error during signature verification:", error);
            verificationResults.push({
                error: error.message || error
            });
        }
    }

    // Performance summary
    const totalSigningTime = (end2 - start1a);
    sendProgress('signing', 'performance', `📊 Performance Summary:`);
    sendProgress('signing', 'performance', `- Round 1a time: ${(end1a - start1a).toFixed(2)}ms`);
    sendProgress('signing', 'performance', `- Round 2 time: ${(end2 - start2).toFixed(2)}ms`);
    sendProgress('signing', 'performance', `- Total signing time: ${totalSigningTime.toFixed(2)}ms`);
    sendProgress('signing', 'performance', `- Precompute tables: ${usePrecomputeTables ? 'ENABLED' : 'DISABLED'}`);
    
    sendProgress('signing', 'complete', `Signing completed! Generated ${validSignatures.length} signatures, verification results: ${verificationResults.filter(r => r.isValid).length}/${verificationResults.length} valid`, 100);

    return {
        presignatures,
        signatures: validSignatures,
        verificationResults,
        performanceMetrics: {
            round1aTime: end1a - start1a,
            round2Time: end2 - start2,
            totalSigningTime,
            precomputeTablesEnabled: usePrecomputeTables
        }
    };
}

// Main test function
async function runFullPipelineTest() {
    try {
        await initializeWasm();

        sendProgress('pipeline', 'start', '🚀 Starting Full CGGMP21 Pipeline Test');
        const startKeygen = Date.now();
        const incompleteKeyShares = await runKeyGeneration();
        console.log('start', Date.now());
        console.log("incompleteKeyShares", incompleteKeyShares);
        const endKeygen = Date.now();
        console.log("Keygen time:", endKeygen - startKeygen, "ms");
        const startAuxgen = Date.now();
        const completeKeyShares = await runAuxGeneration(incompleteKeyShares);
        console.log("completeKeyShares", completeKeyShares);
        const endAuxgen = Date.now();
        console.log("Auxgen time:", endAuxgen - startAuxgen, "ms");
        const startSigning = Date.now();
        const signingResults = await runSigning(completeKeyShares);
        const endSigning = Date.now();
        console.log("Signing time:", endSigning - startSigning, "ms");
        console.log("Total time:", endSigning - startKeygen, "ms");
        console.log('end', Date.now());
        console.log("signingResults", signingResults);
        sendProgress('pipeline', 'complete', '🎉 Full Pipeline Test Completed Successfully!');

        return {
            incompleteKeyShares,
            completeKeyShares,
            signingResults
        };

    } catch (error) {
        postMessage({
            type: 'error',
            data: {
                message: error.message,
                stack: error.stack
            }
        });
        throw error;
    }
}

// Handle messages from main thread
self.onmessage = async function (e) {
    const { type, data, messageId } = e.data;
    console.log('🔧 Worker received message:', { type, messageId, hasData: !!data });

    try {
        switch (type) {
            case 'init':
                console.log('🚀 Worker initializing WASM...');
                await initializeWasm();
                console.log('✅ Worker WASM initialized, sending response...');
                postMessage({ type: 'init_complete', messageId });
                break;

            case 'run_keygen':
                const keyShares = await runKeyGeneration();
                postMessage({
                    type: 'keygen_complete',
                    data: keyShares,
                    messageId
                });
                break;

            case 'run_auxgen':
                const completeShares = await runAuxGeneration(data.incompleteKeyShares);
                postMessage({
                    type: 'auxgen_complete',
                    data: completeShares,
                    messageId
                });
                break;

            case 'run_signing':
                const signingResults = await runSigning(data.completeKeyShares);
                postMessage({
                    type: 'signing_complete',
                    data: signingResults,
                    messageId
                });
                break;

            case 'run_full_pipeline':
                console.log("run_full_pipeline");
                const results = await runFullPipelineTest();
                postMessage({
                    type: 'pipeline_complete',
                    data: results,
                    messageId
                });
                break;

            case 'toggle_precompute_tables':
                usePrecomputeTables = data.enabled;
                if (!usePrecomputeTables) {
                    precomputeTablesCache.clear();
                }
                sendProgress('config', 'precompute', `Precompute tables ${usePrecomputeTables ? 'ENABLED' : 'DISABLED'}`);
                postMessage({
                    type: 'precompute_toggled',
                    data: { enabled: usePrecomputeTables },
                    messageId
                });
                break;

            case 'clear_precompute_cache':
                precomputeTablesCache.clear();
                sendProgress('config', 'cache', 'Precompute tables cache cleared');
                postMessage({
                    type: 'cache_cleared',
                    messageId
                });
                break;
                
            case 'get_precompute_status':
                postMessage({
                    type: 'precompute_status',
                    data: {
                        enabled: usePrecomputeTables,
                        cacheSize: precomputeTablesCache.size
                    },
                    messageId
                });
                break;

            default:
                throw new Error(`Unknown message type: ${type}`);
        }
    } catch (error) {
        postMessage({
            type: 'error',
            data: {
                originalType: type,
                message: error.message,
                stack: error.stack
            },
            messageId
        });
    }
}; 
