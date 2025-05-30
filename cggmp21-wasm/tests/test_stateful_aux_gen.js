import init, { StatefulAuxGenProtocol } from '../pkg/cggmp21_wasm.js';

// Test configuration for auxiliary generation
const parties = [
    {
        i: 0,
        n: 3,
        sid: "aux-gen-test-session-123",
        reliable_broadcast_enforced: false,
        compute_multiexp_table: true,
        compute_crt: true,
        ids: [1, 2]
    },
    {
        i: 1,
        n: 3,
        sid: "aux-gen-test-session-123",
        reliable_broadcast_enforced: false,
        compute_multiexp_table: true,
        compute_crt: true,
        ids: [0, 2]
    },
    {
        i: 2,
        n: 3,
        sid: "aux-gen-test-session-123",
        reliable_broadcast_enforced: false,
        compute_multiexp_table: true,
        compute_crt: true,
        ids: [0, 1]
    }
];

// Initialize protocol instances for all parties
const initProtocols = async (parties) => {
    const protocols = [];
    for (let i = 0; i < parties.length; i++) {
        const party = { ...parties[i] };
        try {
            console.log(`Initializing protocol for party ${i}...`);
            const protocol = await new StatefulAuxGenProtocol(party);
            protocols.push(protocol);
            console.log(`Party ${i} protocol initialized successfully`);
        } catch (error) {
            console.error(`Failed to create protocol for party ${i}:`, error);
            throw error;
        }
    }
    return protocols;
};

// Helper functions for message handling
const createRecipientMap = (items, partyConfig) => {
    const map = {};
    items.forEach((item, idx) => {
        map[idx] = items.filter((_, idx2) => partyConfig[idx].ids.includes(idx2));
    });
    return map;
};

// Protocol round functions
const runRound1 = (protocols) => {
    console.log("Running Round 1: Generate commitments");
    return protocols.map((protocol, idx) => {
        try {
            const commitment = protocol.round1_generate_commitment();
            console.log(`Party ${idx} generated commitment successfully`);
            return commitment;
        } catch (error) {
            console.error(`Party ${idx} failed in round 1:`, error);
            throw error;
        }
    });
};

const setRound1Commitments = (protocols, commitments) => {
    console.log("Setting Round 1 commitments for all parties");
    const commitmentsMap = createRecipientMap(commitments, parties);
    
    protocols.forEach((protocol, idx) => {
        try {
            protocol.set_round1_commitments({
                commitments: commitmentsMap[idx],
                ids: parties[idx].ids
            });
            console.log(`Party ${idx} set ${commitmentsMap[idx].length} round 1 commitments`);
        } catch (error) {
            console.error(`Party ${idx} failed setting round 1 commitments:`, error);
            throw error;
        }
    });
};

const createReliabilityChecks = (protocols) => {
    console.log("Creating reliability checks (if enforced)");
    return protocols.map((protocol, idx) => {
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
            console.error(`Party ${idx} failed creating reliability check:`, error);
            throw error;
        }
    });
};

const runRound2 = (protocols) => {
    console.log("Running Round 2: Get decommitments");
    return protocols.map((protocol, idx) => {
        try {
            const decommitment = protocol.round2_get_decommitment();
            console.log(`Party ${idx} generated decommitment successfully`);
            return decommitment;
        } catch (error) {
            console.error(`Party ${idx} failed in round 2:`, error);
            throw error;
        }
    });
};

const setRound2Decommitments = (protocols, decommitments) => {
    console.log("Setting Round 2 decommitments for all parties");
    const decommitmentsMap = createRecipientMap(decommitments, parties);
    
    protocols.forEach((protocol, idx) => {
        try {
            protocol.set_round2_decommitments({
                decommitments: decommitmentsMap[idx],
                ids: parties[idx].ids
            });
            console.log(`Party ${idx} set ${decommitmentsMap[idx].length} round 2 decommitments`);
        } catch (error) {
            console.error(`Party ${idx} failed setting round 2 decommitments:`, error);
            throw error;
        }
    });
};

const validateRound2Decommitments = (protocols) => {
    console.log("Validating Round 2 decommitments");
    protocols.forEach((protocol, idx) => {
        try {
            protocol.validate_round2_decommitments();
            console.log(`Party ${idx} validated round 2 decommitments successfully`);
        } catch (error) {
            console.error(`Party ${idx} failed validating round 2 decommitments:`, error);
            throw error;
        }
    });
};

const runRound3 = (protocols) => {
    console.log("Running Round 3: Create messages");
    return protocols.map((protocol, idx) => {
        try {
            const messages = protocol.round3_create_messages();
            console.log(`Party ${idx} created round 3 messages successfully`);
            return messages;
        } catch (error) {
            console.error(`Party ${idx} failed in round 3:`, error);
            throw error;
        }
    });
};

const setRound3Messages = (protocols, round3Messages) => {
    console.log("Setting Round 3 messages for all parties");
    
    // Convert the message format - the round3Messages from round3_create_messages() 
    // appears to be in a different format than what set_round3_messages expects
    protocols.forEach((protocol, idx) => {
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
            console.log(`Party ${idx} set ${messagesForParty.length} round 3 messages`);
        } catch (error) {
            console.error(`Party ${idx} failed setting round 3 messages:`, error);
            throw error;
        }
    });
};

const finalizeProtocols = (protocols) => {
    console.log("Finalizing protocols to generate auxiliary info");
    return protocols.map((protocol, idx) => {
        try {
            const auxInfo = protocol.finalize();
            console.log(`Party ${idx} generated auxiliary info successfully`);
            return auxInfo;
        } catch (error) {
            console.error(`Party ${idx} failed finalizing:`, error);
            throw error;
        }
    });
};

// Main test function
async function runTest() {
    try {
        console.log("🚀 Initializing WASM module...");
        await init();
        console.log("✅ WASM module initialized successfully");

        console.log("\n📋 Testing StatefulAuxGenProtocol...");
        console.log("Party configuration:", parties);

        // Initialize protocols
        console.log("\n=== 🔧 Initializing Protocols ===");
        const protocols = await initProtocols(parties);
        console.log("✅ All protocols initialized successfully", protocols);

        // Round 1: Generate commitments
        console.log("\n=== 🔐 Round 1: Commitments ===");
        const commitments = runRound1(protocols);
        console.log(`Generated ${commitments.length} commitments`);
        
        // Set commitments for all parties
        setRound1Commitments(protocols, commitments);

        // Create reliability checks if enforced
        console.log("\n=== 🔒 Reliability Checks ===");
        const reliabilityChecks = createReliabilityChecks(protocols);
        const activeReliabilityChecks = reliabilityChecks.filter(check => check !== null);
        console.log(`Created ${activeReliabilityChecks.length} reliability checks`);

        // Round 2: Get decommitments
        console.log("\n=== 🔓 Round 2: Decommitments ===");
        const decommitments = runRound2(protocols);
        console.log(`Generated ${decommitments.length} decommitments`);

        // Set decommitments for all parties
        setRound2Decommitments(protocols, decommitments);

        // Validate decommitments
        console.log("\n=== ✅ Validating Decommitments ===");
        validateRound2Decommitments(protocols);

        // Round 3: Create messages
        console.log("\n=== 📝 Round 3: Messages ===");
        const round3Messages = runRound3(protocols);
        console.log(`Generated ${round3Messages.length} round 3 message sets`);

        // Set round 3 messages for all parties
        setRound3Messages(protocols, round3Messages);

        // Finalize and generate auxiliary info
        console.log("\n=== 🎯 Finalizing ===");
        const auxInfos = finalizeProtocols(protocols);

        console.log("\n=== 🎉 Test Results ===");
        console.log(`✅ Generated auxiliary info for ${auxInfos.length} parties`);
        auxInfos.forEach((auxInfo, idx) => {
            console.log(`   📊 Party ${idx}: Auxiliary info generated successfully`);
        });

        console.log("\n🎊 Test completed successfully!");
        return {
            commitments,
            reliabilityChecks,
            decommitments,
            round3Messages,
            auxInfos
        };
    } catch (error) {
        console.error("💥 Test failed with error:", error);
        console.error("📋 Error details:", error.message);
        if (error.stack) {
            console.error("🔍 Stack trace:", error.stack);
        }
        throw error;
    }
}

// For browser environment
if (typeof document !== 'undefined') {
    document.getElementById('testButton')?.addEventListener('click', () => {
        const outputElement = document.getElementById('output');
        if (outputElement) {
            outputElement.textContent = 'Running auxiliary generation test...\n';
            
            runTest().then(result => {
                outputElement.textContent += "\n🎉 Test completed successfully!\n";
                outputElement.textContent += `✅ Generated auxiliary info for ${result.auxInfos.length} parties\n`;
                outputElement.textContent += `📊 Protocol rounds completed:\n`;
                outputElement.textContent += `   - Round 1: ${result.commitments.length} commitments\n`;
                outputElement.textContent += `   - Round 2: ${result.decommitments.length} decommitments\n`;
                outputElement.textContent += `   - Round 3: ${result.round3Messages.length} proof messages\n`;
                outputElement.textContent += `   - Final: ${result.auxInfos.length} auxiliary info objects\n`;
            }).catch(error => {
                outputElement.textContent += "\n❌ Test failed with error: " + error.message + "\n";
                outputElement.textContent += "Check console for detailed error information.\n";
            });
        }
    });
}

// Export for both browser and Node.js environments
if (typeof module !== 'undefined') {
    module.exports = { runTest };
}

// Export for ES6 modules (browser)
export { runTest }; 
