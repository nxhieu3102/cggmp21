// test_hierarchical_worker.js - Web Worker for Hierarchical Threshold CGGMP21 computations
import init, {
    StatefulHierarchicalThresholdKeygenProtocol,
    StatefulAuxGenProtocol,
    StatefulSigningProtocol
} from '../pkg/cggmp21_wasm.js';

// Worker state
let wasmInitialized = false;

// Test configuration for 3-of-4 hierarchical threshold with ranks [0, 0, 1, 1]
// Following the rule: for any t shares with ranks (r₁, r₂, ..., rₜ) sorted by rank, 
// recovery is possible if and only if rᵢ ≤ i-1 for all i ∈ {1, 2, ..., t}
const parties = [
    {
        i: 0, t: 3, ranks: [0, 0, 1, 1], n: 4,
        sid: "hierarchical-threshold-test-session",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [1, 2, 3] // Other parties this party communicates with
    },
    {
        i: 1, t: 3, ranks: [0, 0, 1, 1], n: 4,
        sid: "hierarchical-threshold-test-session",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [0, 2, 3]
    },
    {
        i: 2, t: 3, ranks: [0, 0, 1, 1], n: 4,
        sid: "hierarchical-threshold-test-session",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [0, 1, 3]
    },
    {
        i: 3, t: 3, ranks: [0, 0, 1, 1], n: 4,
        sid: "hierarchical-threshold-test-session",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [0, 1, 2]
    }
];

// Message to sign (hex-encoded)
const MESSAGE_TO_SIGN = "48656c6c6f2c20576f726c6421"; // "Hello, World!" in hex

// Progress reporting helper
const sendProgress = (phase, round, message, progress = null) => {
    console.log("Worker sendProgress", phase, round, message, progress);
    postMessage({
        type: 'progress',
        data: { phase, round, message, progress }
    });
};

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

// Validate hierarchical threshold configuration
const validateConfiguration = (partyConfig) => {
    console.log("Validating hierarchical threshold configuration...");
    
    const n = partyConfig.length;
    const t = partyConfig[0].t;
    const ranks = partyConfig[0].ranks;
    
    // Basic validation
    if (t > n) {
        throw new Error(`Invalid threshold: t=${t} > n=${n}`);
    }
    
    if (ranks.length !== n) {
        throw new Error(`Ranks array length (${ranks.length}) doesn't match number of parties (${n})`);
    }
    
    // Validate rank constraints
    for (let i = 0; i < ranks.length; i++) {
        if (ranks[i] >= t) {
            throw new Error(`Invalid rank: party ${i} has rank ${ranks[i]} >= threshold ${t}`);
        }
    }
    
    // Check for valid authorized sets
    let validSets = 0;
    
    // Enumerate all possible t-sized subsets
    for (let mask = 0; mask < (1 << n); mask++) {
        const selectedParties = [];
        for (let i = 0; i < n; i++) {
            if (mask & (1 << i)) {
                selectedParties.push(i);
            }
        }
        
        if (selectedParties.length === t) {
            const selectedRanks = selectedParties.map(i => ranks[i]).sort((a, b) => a - b);
            let isValid = true;
            for (let j = 0; j < t; j++) {
                if (selectedRanks[j] > j) {
                    isValid = false;
                    break;
                }
            }
            if (isValid) {
                validSets++;
                console.log(`Valid authorized set: {${selectedParties.join(',')}} with ranks [${selectedRanks.join(',')}]`);
            }
        }
    }
    
    if (validSets === 0) {
        throw new Error("No valid authorized sets found for the given rank configuration");
    }
    
    console.log(`Configuration validated: t=${t}, n=${n}, valid authorized sets=${validSets}`);
    console.log(`Rank distribution: ${ranks.map((r, i) => `Party${i}:${r}`).join(', ')}`);
    
    return { t, n, ranks, validSets };
};

// Initialize WASM module
async function initializeWasm() {
    if (!wasmInitialized) {
        await init();
        wasmInitialized = true;
        sendProgress('init', '', 'WASM module initialized successfully');
    }
}

// Phase 1: Hierarchical Threshold Key Generation
async function runHierarchicalKeyGeneration() {
    sendProgress('keygen', 'start', 'Starting Hierarchical Threshold Key Generation Phase');
    
    // Validate configuration first
    const validationResult = validateConfiguration(parties);
    sendProgress('keygen', 'validation', `Configuration validated: ${validationResult.validSets} valid authorized sets`);

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

    console.log("[keygenProtocols]: ", keygenProtocols);
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

    // Round 2: Generate decommitments and unicast messages (parallelized)
    sendProgress('keygen', 'round2', 'Generating decommitments and shares...', 40);
    
    const decommitments = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const decommitment = protocol.round2_get_decommitment();
                    console.log(`Party ${idx} generated decommitment successfully`);
                    return decommitment;
                } catch (error) {
                    console.error(`Party ${idx} failed getting round 2 decommitment: ${error.message}`);
                    throw error;
                }
            })
        )
    );
    
    const unicastMessages = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const messages = protocol.round2_get_unicast_messages();
                    console.log(`Party ${idx} generated ${messages.length} unicast messages`);
                    return messages;
                } catch (error) {
                    console.error(`Party ${idx} failed getting round 2 unicast messages: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Set Round 2 data for all parties
    sendProgress('keygen', 'round2', 'Setting decommitments and sigma shares...', 55);
    const decommitmentsMap = createRecipientMap(decommitments, parties);
    const sigmasMap = createUnicastMap(unicastMessages, parties);
    
    await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {

                    console.log(`[runHierarchicalKeyGeneration] decommitmentsMap ${idx} with size = ${decommitmentsMap[idx].length}`, JSON.stringify(decommitmentsMap[idx]));
                    console.log(`[runHierarchicalKeyGeneration] sigmasMap ${idx} with size = ${sigmasMap[idx].length}`, JSON.stringify(sigmasMap[idx]));

                    console.log(`[runHierarchicalKeyGeneration] parties[idx].ids ${idx}`, parties[idx].ids);



                    // Set decommitments
                    protocol.set_round2_decommitments({
                        decommitments: decommitmentsMap[idx],
                        ids: parties[idx].ids
                    });
                    console.log(`Party ${idx} set ${decommitmentsMap[idx].length} round 2 decommitments`, JSON.stringify(decommitmentsMap[idx]));
                    
                    // Set sigma shares
                    protocol.set_round2_sigmas({
                        sigmas: sigmasMap[idx],
                        ids: parties[idx].ids
                    });
                    console.log(`Party ${idx} set ${sigmasMap[idx].length} round 2 sigma shares`, JSON.stringify(sigmasMap[idx]));
                } catch (error) {
                    console.error(`Party ${idx} failed setting round 2 data: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Validate Round 2 data and prepare for Round 3
    sendProgress('keygen', 'round2', 'Validating round 2 data...', 65);
    await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    protocol.validate_round2_and_prepare_round3();
                    console.log(`Party ${idx} validated round 2 data successfully`);
                } catch (error) {
                    console.error(`Party ${idx} failed validating round 2 data: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Round 3: Generate Schnorr proofs (parallelized)
    sendProgress('keygen', 'round3', 'Generating Schnorr proofs...', 75);
    const schnorrProofs = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const proof = protocol.round3_generate_proof();
                    console.log(`Party ${idx} generated Schnorr proof successfully`);
                    return proof;
                } catch (error) {
                    console.error(`Party ${idx} failed generating round 3 proof: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Set Round 3 Schnorr proofs for all parties
    sendProgress('keygen', 'round3', 'Setting Schnorr proofs...', 85);
    const proofsMap = createRecipientMap(schnorrProofs, parties);
    
    await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    protocol.set_round3_schnorr_proofs({
                        sch_proof: proofsMap[idx],
                        ids: parties[idx].ids
                    });
                    console.log(`Party ${idx} set ${proofsMap[idx].length} round 3 Schnorr proofs`);
                } catch (error) {
                    console.error(`Party ${idx} failed setting round 3 proofs: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Finalize and generate incomplete key shares (parallelized)
    sendProgress('keygen', 'final', 'Generating hierarchical threshold key shares...', 90);
    const incompleteKeyShares = await Promise.all(
        keygenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const keyShare = protocol.finalize_key_generation();
                    console.log(`Party ${idx} generated hierarchical threshold key share successfully`);
                    return keyShare;
                } catch (error) {
                    console.error(`Party ${idx} failed finalizing key generation: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Validate key shares
    console.log("Validating generated hierarchical key shares...");
    incompleteKeyShares.forEach((keyShare, idx) => {
        if (keyShare && typeof keyShare === 'object') {
            console.log(`Party ${idx}: Hierarchical key share generated with rank ${parties[idx].ranks[idx]}`);
        } else {
            throw new Error(`Invalid hierarchical key share for party ${idx}`);
        }
    });

    sendProgress('keygen', 'complete', `Hierarchical threshold key generation completed! Generated ${incompleteKeyShares.length} incomplete key shares`, 100);
    
    return {
        incompleteKeyShares,
        validationResult,
        commitments,
        reliabilityChecks,
        decommitments,
        unicastMessages,
        schnorrProofs
    };
}

// Phase 2: Auxiliary Information Generation
async function runAuxGeneration(incompleteKeyShares) {
    sendProgress('auxgen', 'start', 'Starting Auxiliary Generation Phase');

    const auxGenProtocols = await Promise.all(
        parties.map(async (party, idx) => {
            try {
                console.log(`Initializing auxiliary generation protocol for party ${idx}...`);
                const protocol = await new StatefulAuxGenProtocol({
                    ...party,
                    sid: party.sid + "-auxgen",
                    compute_multiexp_table: false,
                    compute_crt: false
                });
                console.log(`Party ${idx} auxiliary generation protocol initialized successfully`);
                return protocol;
            } catch (error) {
                console.error(`Failed to create auxiliary generation protocol for party ${idx}: ${error.message}`);
                throw error;
            }
        })
    );

    // Round 1: Generate commitments (parallelized)
    sendProgress('auxgen', 'round1', 'Generating commitments...', 25);
    const commitments = await Promise.all(
        auxGenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const commitment = protocol.round1_generate_commitment();
                    console.log(`Party ${idx} generated auxiliary commitment successfully`);
                    return commitment;
                } catch (error) {
                    console.error(`Party ${idx} failed generating auxiliary commitment: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    const commitmentsMap = createRecipientMap(commitments, parties);
    await Promise.all(
        auxGenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    protocol.set_round1_commitments({
                        commitments: commitmentsMap[idx],
                        ids: parties[idx].ids
                    });
                    console.log(`Party ${idx} set ${commitmentsMap[idx].length} auxiliary round 1 commitments`);
                } catch (error) {
                    console.error(`Party ${idx} failed setting auxiliary round 1 commitments: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Round 2: Get decommitments (parallelized)
    sendProgress('auxgen', 'round2', 'Getting decommitments...', 50);
    const decommitments = await Promise.all(
        auxGenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const decommitment = protocol.round2_get_decommitment();
                    console.log(`Party ${idx} generated auxiliary decommitment successfully`);
                    return decommitment;
                } catch (error) {
                    console.error(`Party ${idx} failed getting auxiliary decommitment: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    const decommitmentsMap = createRecipientMap(decommitments, parties);

    await Promise.all(
        auxGenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    protocol.set_round2_decommitments({
                        decommitments: decommitmentsMap[idx],
                        ids: parties[idx].ids
                    });
                    console.log(`Party ${idx} set ${decommitmentsMap[idx].length} auxiliary round 2 decommitments`);
                    
                    protocol.validate_round2_decommitments();
                    console.log(`Party ${idx} validated auxiliary round 2 decommitments`);
                } catch (error) {
                    console.error(`Party ${idx} failed with auxiliary round 2 decommitments: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Round 3: Create messages (parallelized)
    sendProgress('auxgen', 'round3', 'Creating messages...', 75);
    const round3Messages = await Promise.all(
        auxGenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const messages = protocol.round3_create_messages();
                    console.log(`Party ${idx} created auxiliary round 3 messages successfully`);
                    return messages;
                } catch (error) {
                    console.error(`Party ${idx} failed creating auxiliary round 3 messages: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    // Set round 3 messages and finalize (parallelized)
    sendProgress('auxgen', 'final', 'Finalizing auxiliary info...', 90);

    // Route round 3 messages to each party
    await Promise.all(
        auxGenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
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

                    protocol.set_round3_messages({
                        messages: messagesForParty,
                        ids: parties[idx].ids
                    });
                    console.log(`Party ${idx} set ${messagesForParty.length} auxiliary round 3 messages`);
                } catch (error) {
                    console.error(`Party ${idx} failed setting auxiliary round 3 messages: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    const auxInfos = await Promise.all(
        auxGenProtocols.map((protocol, idx) =>
            Promise.resolve().then(() => {
                try {
                    const auxInfo = protocol.finalize();
                    console.log(`Party ${idx} finalized auxiliary information successfully`);
                    return auxInfo;
                } catch (error) {
                    console.error(`Party ${idx} failed finalizing auxiliary information: ${error.message}`);
                    throw error;
                }
            })
        )
    );

    const completeKeyShares = incompleteKeyShares.map((incompleteShare, idx) => {
        return {
            core: incompleteShare,
            aux: auxInfos[idx],
            party_index: idx,
            rank: parties[idx].ranks[idx]
        };
    });

    sendProgress('auxgen', 'complete', `Auxiliary generation completed! Generated ${completeKeyShares.length} complete key shares`, 100);
    
    return {
        completeKeyShares,
        auxInfos,
        round3Messages
    };
}

// Phase 3: Hierarchical Threshold Signing
async function runHierarchicalSigning(completeKeyShares) {
    sendProgress('signing', 'start', 'Starting Hierarchical Threshold Signing Phase');
    
    // Use configuration: n=4, t=3, ranks=[0,0,1,1], signers=[0,1,2] (parties with ranks [0,0,1])
    const signingParties = [0, 1, 2]; // Party indices that will participate in signing
    const signingKeyShares = signingParties.map(idx => completeKeyShares[idx]);
    
    // Validate signing configuration according to hierarchical rules
    // For valid signing set: if ranks are sorted as r1 ≤ r2 ≤ ... ≤ rt, then ri ≤ i-1 for all i
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
            signerRanks
        }
    };
}

// Main test function
async function runFullHierarchicalPipelineTest() {
    try {
        await initializeWasm();

        sendProgress('pipeline', 'start', '🚀 Starting Full Hierarchical CGGMP21 Pipeline Test');
        sendProgress('pipeline', 'config', `Configuration: ${parties[0].t}-of-${parties[0].n} hierarchical threshold with ranks [${parties[0].ranks.join(',')}]`);
        
        const startKeygen = Date.now();
        const keygenResults = await runHierarchicalKeyGeneration();
        const endKeygen = Date.now();
        console.log("Hierarchical Keygen time:", endKeygen - startKeygen, "ms");
        
        const startAuxgen = Date.now();
        const auxgenResults = await runAuxGeneration(keygenResults.incompleteKeyShares);
        const endAuxgen = Date.now();
        console.log("Auxgen time:", endAuxgen - startAuxgen, "ms");
        
        const startSigning = Date.now();
        const signingResults = await runHierarchicalSigning(auxgenResults.completeKeyShares);
        const endSigning = Date.now();
        console.log("Hierarchical Signing time:", endSigning - startSigning, "ms");
        
        console.log("Total time:", endSigning - startKeygen, "ms");
        
        sendProgress('pipeline', 'complete', '🎉 Full Hierarchical Pipeline Test Completed Successfully!');

        return {
            keygenResults,
            auxgenResults,
            signingResults,
            performanceMetrics: {
                keygenTime: endKeygen - startKeygen,
                auxgenTime: endAuxgen - startAuxgen,
                signingTime: endSigning - startSigning,
                totalTime: endSigning - startKeygen
            }
        };

    } catch (error) {
        console.log(`Hierarchical pipeline test failed: ${JSON.stringify(error)}`);
        console.error("Hierarchical pipeline test failed:", error);
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

            case 'run_hierarchical_keygen':
                const keygenResults = await runHierarchicalKeyGeneration();
                postMessage({
                    type: 'hierarchical_keygen_complete',
                    data: keygenResults,
                    messageId
                });
                break;

            case 'run_hierarchical_auxgen':
                const auxgenResults = await runAuxGeneration(data.incompleteKeyShares);
                postMessage({
                    type: 'hierarchical_auxgen_complete',
                    data: auxgenResults,
                    messageId
                });
                break;

            case 'run_hierarchical_signing':
                const signingResults = await runHierarchicalSigning(data.completeKeyShares);
                postMessage({
                    type: 'hierarchical_signing_complete',
                    data: signingResults,
                    messageId
                });
                break;

            case 'run_hierarchical_pipeline':
                console.log("run_hierarchical_pipeline");
                const results = await runFullHierarchicalPipelineTest();
                postMessage({
                    type: 'hierarchical_pipeline_complete',
                    data: results,
                    messageId
                });
                break;

            case 'validate_hierarchical_config':
                const validationResult = validateConfiguration(parties);
                postMessage({
                    type: 'hierarchical_config_validated',
                    data: validationResult,
                    messageId
                });
                break;

            default:
                throw new Error(`Unknown message type: ${type}`);
        }
    } catch (error) {
        console.error("Hierarchical worker error:", error);
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
