// test_hierarchical_signing_worker.js - Web Worker for hierarchical CGGMP21 computations
import init, {
    StatefulHierarchicalThresholdKeygenProtocol,
    StatefulAuxGenProtocol,
    StatefulSigningProtocol
} from '../pkg/cggmp21_wasm.js';

// Worker state
let wasmInitialized = false;

// Test configuration for hierarchical threshold signing: n=4, t=3, ranks=[0,0,1,1]
const parties = [
    {
        i: 0, t: 3, n: 4,
        ranks: [0, 0, 1, 1], // ranks for all parties
        sid: "test-hierarchical-session-456",
        reliable_broadcast_enforced: false,
        ids: [1, 2, 3] // Other parties this party communicates with
    },
    {
        i: 1, t: 3, n: 4,
        ranks: [0, 0, 1, 1],
        sid: "test-hierarchical-session-456",
        reliable_broadcast_enforced: false,
        ids: [0, 2, 3]
    },
    {
        i: 2, t: 3, n: 4,
        ranks: [0, 0, 1, 1],
        sid: "test-hierarchical-session-456",
        reliable_broadcast_enforced: false,
        ids: [0, 1, 3]
    },
    {
        i: 3, t: 3, n: 4,
        ranks: [0, 0, 1, 1],
        sid: "test-hierarchical-session-456",
        reliable_broadcast_enforced: false,
        ids: [0, 1, 2]
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

const createUnicastMap = (unicastMessages, partyConfig) => {
    const map = {};
    
    // Initialize map with empty arrays for each party
    partyConfig.forEach((_, idx) => {
        map[idx] = [];
    });
    
    // Route unicast messages to recipients  
    unicastMessages.forEach((partyMessages, senderIdx) => {
        if (Array.isArray(partyMessages)) {
            partyMessages.forEach(msgPair => {
                if (Array.isArray(msgPair) && msgPair.length === 2) {
                    const [recipientId, message] = msgPair;
                    if (map[recipientId]) {
                        map[recipientId].push(message);
                    }
                }
            });
        }
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

// Validate hierarchical configuration
const validateConfiguration = (partyConfig) => {
    const n = partyConfig.length;
    const t = partyConfig[0].t;
    const ranks = partyConfig[0].ranks;
    
    console.log(`Validating n=${n}, t=${t}, ranks=${JSON.stringify(ranks)}`);
    
    // Validate basic constraints
    if (ranks.length !== n) {
        throw new Error(`Ranks array length (${ranks.length}) must equal n (${n})`);
    }
    
    if (ranks.some(r => r >= t)) {
        throw new Error(`All ranks must be < t (${t}). Found: ${ranks}`);
    }
    
    // Calculate valid signing combinations
    const validSets = [];
    const combinations = [];
    
    // Generate all combinations of t parties
    function getCombinations(arr, size) {
        if (size === 1) return arr.map(x => [x]);
        return arr.flatMap((x, i) => 
            getCombinations(arr.slice(i + 1), size - 1).map(combo => [x, ...combo])
        );
    }
    
    const allCombinations = getCombinations([...Array(n).keys()], t);
    
    for (const combo of allCombinations) {
        const comboRanks = combo.map(i => ranks[i]).sort((a, b) => a - b);
        const isValid = comboRanks.every((rank, idx) => rank <= idx);
        
        combinations.push({
            parties: combo,
            ranks: comboRanks,
            valid: isValid
        });
        
        if (isValid) {
            validSets.push(combo);
        }
    }
    
    console.log('All combinations:', combinations);
    console.log('Valid authorized sets:', validSets);
    
    return {
        n, t, ranks,
        combinations,
        validSets,
        validCount: validSets.length,
        totalCombinations: allCombinations.length
    };
};

// Initialize WASM module
async function initializeWasm() {
    if (!wasmInitialized) {
        await init();
        wasmInitialized = true;
        sendProgress('init', '', 'WASM module initialized successfully');
    }
}

// Phase 1: Hierarchical Key Generation
async function runHierarchicalKeyGeneration() {
    sendProgress('keygen', 'start', 'Starting Hierarchical Threshold Key Generation Phase');
    
    // Validate configuration first
    const validationResult = validateConfiguration(parties);
    sendProgress('keygen', 'validation', `Configuration validated: ${validationResult.validSets.length} valid authorized sets`);

    // Initialize hierarchical threshold keygen protocols
    const keygenProtocols = [];

    for (let i = 0; i < parties.length; i++) {
        const party = { ...parties[i] };
        try {
            sendProgress('keygen', 'init', `Initializing protocol for party ${i} (rank: ${party.ranks[i]})...`);
            const protocol = new StatefulHierarchicalThresholdKeygenProtocol(party);
            keygenProtocols.push(protocol);
            console.log(`Party ${i} hierarchical threshold protocol initialized successfully`);
        } catch (error) {
            console.error(`Failed to create hierarchical threshold protocol for party ${i}: ${error.message}`);
            throw error;
        }
    }

    // Round 1: Generate commitments (parallelized)
    sendProgress('keygen', 'round1', 'Generating commitments...', 15);
    const commitments = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const commitment = protocol.round1_generate_commitment();
                    console.log(`Party ${idx} (rank ${parties[idx].ranks[idx]}) generated commitment successfully`);
                    return commitment;
                } catch (error) {
                    console.error(`Party ${idx} failed in round 1: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Set Round 1 commitments for all parties
    sendProgress('keygen', 'round1', 'Setting commitments for all parties...', 25);
    const commitmentsMap = createRecipientMap(commitments, parties);
    
    await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    protocol.set_round1_commitments({
                        commitments: commitmentsMap[idx],
                        ids: parties[idx].ids
                    });
                    console.log(`Party ${idx} set ${commitmentsMap[idx].length} round 1 commitments`);
                } catch (error) {
                    console.error(`Party ${idx} failed setting round 1 commitments: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Create reliability checks if enforced
    sendProgress('keygen', 'round1', 'Creating reliability checks...', 30);
    const reliabilityChecks = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    if (parties[idx].reliable_broadcast_enforced) {
                        const reliabilityCheck = protocol.create_reliability_check();
                        console.log(`Party ${idx} created reliability check`);
                        return reliabilityCheck;
                    } else {
                        console.log(`Party ${idx} skipping reliability check (not enforced)`);
                        return null;
                    }
                } catch (error) {
                    console.error(`Party ${idx} failed creating reliability check: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Round 2: Get decommitments and unicast messages
    sendProgress('keygen', 'round2', 'Getting decommitments...', 40);
    const decommitments = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const decommitment = protocol.round2_get_decommitment();
                    console.log(`Party ${idx} generated decommitment successfully`);
                    return decommitment;
                } catch (error) {
                    console.error(`Party ${idx} failed in round 2 decommitment: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    sendProgress('keygen', 'round2', 'Creating unicast messages...', 50);
    const unicastMessages = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const messages = protocol.round2_create_unicast_messages();
                    console.log(`Party ${idx} created ${messages.length} unicast messages`);
                    return messages;
                } catch (error) {
                    console.error(`Party ${idx} failed creating unicast messages: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Set Round 2 data for all parties
    sendProgress('keygen', 'round2', 'Setting round 2 data...', 60);
    const decommitmentsMap = createRecipientMap(decommitments, parties);
    const unicastMap = createUnicastMap(unicastMessages, parties);

    await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    protocol.set_round2_decommitments({
                        decommitments: decommitmentsMap[idx],
                        ids: parties[idx].ids
                    });
                    console.log(`Party ${idx} set ${decommitmentsMap[idx].length} round 2 decommitments`);
                    
                    protocol.set_round2_unicast_messages({
                        messages: unicastMap[idx],
                        ids: parties[idx].ids
                    });
                    console.log(`Party ${idx} set ${unicastMap[idx].length} round 2 unicast messages`);
                    
                    // Validate round 2 data
                    const validation = protocol.validate_round2_data();
                    console.log(`Party ${idx} round 2 validation: ${validation}`);
                } catch (error) {
                    console.error(`Party ${idx} failed setting round 2 data: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Round 3: Create Schnorr proofs
    sendProgress('keygen', 'round3', 'Creating Schnorr proofs...', 70);
    const schnorrProofs = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const proof = protocol.round3_create_schnorr_proof();
                    console.log(`Party ${idx} created Schnorr proof successfully`);
                    return proof;
                } catch (error) {
                    console.error(`Party ${idx} failed creating Schnorr proof: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Set Round 3 data and generate key shares
    sendProgress('keygen', 'final', 'Generating hierarchical key shares...', 85);
    const schnorrProofsMap = createRecipientMap(schnorrProofs, parties);

    const incompleteKeyShares = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    protocol.set_round3_schnorr_proofs({
                        proofs: schnorrProofsMap[idx],
                        ids: parties[idx].ids
                    });
                    console.log(`Party ${idx} set ${schnorrProofsMap[idx].length} Schnorr proofs`);
                    
                    const keyShare = protocol.generate_key_share();
                    console.log(`Party ${idx} generated hierarchical key share successfully`);
                    return keyShare;
                } catch (error) {
                    console.error(`Party ${idx} failed generating key share: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    sendProgress('keygen', 'complete', `Hierarchical key generation completed! Generated ${incompleteKeyShares.length} key shares`, 100);
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
    sendProgress('auxgen', 'round1', 'Generating commitments...', 25);
    const commitments = await Promise.all(
        auxGenProtocols.map(protocol =>
            Promise.resolve(protocol.round1_generate_commitment())
        )
    );

    const commitmentsMap = createRecipientMap(commitments, parties);
    await Promise.all(
        auxGenProtocols.map(async (protocol, idx) => {
            return Promise.resolve(protocol.set_round1_commitments({
                commitments: commitmentsMap[idx],
                ids: parties[idx].ids
            }));
        })
    );

    // Round 2: Get decommitments (parallelized)
    sendProgress('auxgen', 'round2', 'Getting decommitments...', 50);
    const decommitments = await Promise.all(
        auxGenProtocols.map(protocol =>
            Promise.resolve(protocol.round2_get_decommitment())
        )
    );

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

    const setRound3Messages = async (protocols, round3Messages) => {
        await Promise.all(
            protocols.map(async (protocol, idx) => {
                try {
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

    await setRound3Messages(auxGenProtocols, round3Messages);

    // Set round 3 messages and finalize (parallelized)
    sendProgress('auxgen', 'final', 'Finalizing auxiliary info...', 90);

    const auxInfos = await Promise.all(
        auxGenProtocols.map((protocol, idx) =>
            Promise.resolve(protocol.finalize())
        )
    );

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

// Phase 3: Hierarchical Threshold Signing
async function runHierarchicalSigning(completeKeyShares) {
    sendProgress('signing', 'start', 'Starting Hierarchical Threshold Signing Phase');
    
    // Use configuration: n=4, t=3, ranks=[0,0,1,1], signers=[0,1,2] (parties with ranks [0,0,1])
    const signingParties = [0, 1, 2]; // Party indices
    const signingKeyShares = signingParties.map(idx => completeKeyShares[idx]);
    
    // Validate signing configuration
    const signerRanks = signingParties.map(idx => parties[idx].ranks[idx]).sort((a, b) => a - b);
    const isValidSigningSet = signerRanks.every((rank, idx) => rank <= idx);
    
    sendProgress('signing', 'validation', `Signing parties: [${signingParties.join(', ')}] with ranks [${signerRanks.join(', ')}]`);
    sendProgress('signing', 'validation', `Valid signing set: ${isValidSigningSet ? 'YES' : 'NO'}`);
    
    if (!isValidSigningSet) {
        throw new Error(`Invalid signing set: ranks [${signerRanks.join(', ')}] violate hierarchical constraints`);
    }

    // Create hierarchical signing protocols (no precompute tables as requested)
    const signingProtocols = signingParties.map((globalIdx, localIdx) => {
        const protocol = new StatefulSigningProtocol({
            i: localIdx,
            signing_parties: [0, 1, 2], // Local indices in signing group
            sid: parties[globalIdx].sid + "-signing",
            reliable_broadcast_enforced: false,
            message_hex: MESSAGE_TO_SIGN,
            enable_precomputable: false // Disable precompute tables as requested
        }, signingKeyShares[localIdx]);
        
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
                    console.log(`✅ Hierarchical signature ${result.signatureIndex} verification: VALID`);
                } else {
                    console.log(`❌ Hierarchical signature ${result.signatureIndex} verification: INVALID`);
                }
            });
        } catch (error) {
            console.error("Error during hierarchical signature verification:", error);
            verificationResults.push({
                error: error.message || error
            });
        }
    }

    // Performance summary
    const totalSigningTime = (end2 - start1a);
    sendProgress('signing', 'performance', `📊 Hierarchical Signing Performance Summary:`);
    sendProgress('signing', 'performance', `- Round 1a time: ${(end1a - start1a).toFixed(2)}ms`);
    sendProgress('signing', 'performance', `- Round 2 time: ${(end2 - start2).toFixed(2)}ms`);
    sendProgress('signing', 'performance', `- Total signing time: ${totalSigningTime.toFixed(2)}ms`);
    sendProgress('signing', 'performance', `- Precompute tables: DISABLED (as requested)`);
    sendProgress('signing', 'performance', `- Signing parties: [${signingParties.join(', ')}] with ranks [${signerRanks.join(', ')}]`);
    
    sendProgress('signing', 'complete', `Hierarchical signing completed! Generated ${validSignatures.length} signatures, verification results: ${verificationResults.filter(r => r.isValid).length}/${verificationResults.length} valid`, 100);

    return {
        presignatures,
        signatures: validSignatures,
        verificationResults,
        performanceMetrics: {
            round1aTime: end1a - start1a,
            round2Time: end2 - start2,
            totalSigningTime,
            precomputeTablesEnabled: false,
            signingParties,
            signerRanks,
            isHierarchical: true
        }
    };
}

// Main test function
async function runFullHierarchicalPipelineTest() {
    try {
        await initializeWasm();

        sendProgress('pipeline', 'start', '🚀 Starting Full Hierarchical CGGMP21 Pipeline Test');
        sendProgress('pipeline', 'config', `Configuration: n=${parties.length}, t=${parties[0].t}, ranks=[${parties[0].ranks.join(', ')}]`);
        
        const startKeygen = Date.now();
        const incompleteKeyShares = await runHierarchicalKeyGeneration();
        const endKeygen = Date.now();
        console.log("Hierarchical Keygen time:", endKeygen - startKeygen, "ms");
        
        const startAuxgen = Date.now();
        const completeKeyShares = await runAuxGeneration(incompleteKeyShares);
        const endAuxgen = Date.now();
        console.log("Auxgen time:", endAuxgen - startAuxgen, "ms");
        
        const startSigning = Date.now();
        const signingResults = await runHierarchicalSigning(completeKeyShares);
        const endSigning = Date.now();
        console.log("Hierarchical Signing time:", endSigning - startSigning, "ms");
        console.log("Total hierarchical pipeline time:", endSigning - startKeygen, "ms");
        
        sendProgress('pipeline', 'complete', '🎉 Full Hierarchical Pipeline Test Completed Successfully!');

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
    console.log('🔧 Hierarchical Worker received message:', { type, messageId, hasData: !!data });

    try {
        switch (type) {
            case 'init':
                console.log('🚀 Hierarchical Worker initializing WASM...');
                await initializeWasm();
                console.log('✅ Hierarchical Worker WASM initialized, sending response...');
                postMessage({ type: 'init_complete', messageId });
                break;

            case 'validate_hierarchical_config':
                const validation = validateConfiguration(parties);
                postMessage({
                    type: 'config_validated',
                    data: validation,
                    messageId
                });
                break;

            case 'run_hierarchical_keygen':
                const keyShares = await runHierarchicalKeyGeneration();
                postMessage({
                    type: 'keygen_complete',
                    data: keyShares,
                    messageId
                });
                break;

            case 'run_hierarchical_auxgen':
                const completeShares = await runAuxGeneration(data.incompleteKeyShares);
                postMessage({
                    type: 'auxgen_complete',
                    data: completeShares,
                    messageId
                });
                break;

            case 'run_hierarchical_signing':
                const signingResults = await runHierarchicalSigning(data.completeKeyShares);
                postMessage({
                    type: 'signing_complete',
                    data: signingResults,
                    messageId
                });
                break;

            case 'run_hierarchical_pipeline':
                console.log("run_hierarchical_pipeline");
                const results = await runFullHierarchicalPipelineTest();
                postMessage({
                    type: 'pipeline_complete',
                    data: results,
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
