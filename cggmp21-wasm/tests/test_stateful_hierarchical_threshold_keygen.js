import init, { StatefulHierarchicalThresholdKeygenProtocol } from '../pkg/cggmp21_wasm.js';

// Test configuration for hierarchical threshold key generation
// Example: 3-of-4 hierarchical threshold with specific ranks
const parties = [
    {
        i: 0,
        t: 3,
        ranks: [0, 1, 1, 2],  // Ranks for all parties
        n: 4,
        sid: "hierarchical-threshold-test-session-456",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [1, 2, 3]  // Other parties this party communicates with
    },
    {
        i: 1,
        t: 3,
        ranks: [0, 1, 1, 2],
        n: 4,
        sid: "hierarchical-threshold-test-session-456",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [0, 2, 3]
    },
    {
        i: 2,
        t: 3,
        ranks: [0, 1, 1, 2],
        n: 4,
        sid: "hierarchical-threshold-test-session-456",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [0, 1, 3]
    },
    {
        i: 3,
        t: 3,
        ranks: [0, 1, 1, 2],
        n: 4,
        sid: "hierarchical-threshold-test-session-456",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [0, 1, 2]
    }
];

// Alternative test configurations for different scenarios
const testConfigurations = {
    small: {
        description: "2-of-3 Hierarchical Threshold (ranks: [0, 1, 1])",
        parties: [
            {
                i: 0, t: 2, ranks: [0, 1, 1], n: 3,
                sid: "hierarchical-test-small", reliable_broadcast_enforced: false,
                hd_enabled: false, ids: [1, 2]
            },
            {
                i: 1, t: 2, ranks: [0, 1, 1], n: 3,
                sid: "hierarchical-test-small", reliable_broadcast_enforced: false,
                hd_enabled: false, ids: [0, 2]
            },
            {
                i: 2, t: 2, ranks: [0, 1, 1], n: 3,
                sid: "hierarchical-test-small", reliable_broadcast_enforced: false,
                hd_enabled: false, ids: [0, 1]
            }
        ]
    },
    medium: {
        description: "3-of-4 Hierarchical Threshold (ranks: [0, 1, 1, 2])",
        parties: parties  // Use the default configuration
    },
    large: {
        description: "4-of-6 Hierarchical Threshold (ranks: [0, 1, 1, 2, 2, 3])",
        parties: [
            {
                i: 0, t: 4, ranks: [0, 1, 1, 2, 2, 3], n: 6,
                sid: "hierarchical-test-large", reliable_broadcast_enforced: false,
                hd_enabled: false, ids: [1, 2, 3, 4, 5]
            },
            {
                i: 1, t: 4, ranks: [0, 1, 1, 2, 2, 3], n: 6,
                sid: "hierarchical-test-large", reliable_broadcast_enforced: false,
                hd_enabled: false, ids: [0, 2, 3, 4, 5]
            },
            {
                i: 2, t: 4, ranks: [0, 1, 1, 2, 2, 3], n: 6,
                sid: "hierarchical-test-large", reliable_broadcast_enforced: false,
                hd_enabled: false, ids: [0, 1, 3, 4, 5]
            },
            {
                i: 3, t: 4, ranks: [0, 1, 1, 2, 2, 3], n: 6,
                sid: "hierarchical-test-large", reliable_broadcast_enforced: false,
                hd_enabled: false, ids: [0, 1, 2, 4, 5]
            },
            {
                i: 4, t: 4, ranks: [0, 1, 1, 2, 2, 3], n: 6,
                sid: "hierarchical-test-large", reliable_broadcast_enforced: false,
                hd_enabled: false, ids: [0, 1, 2, 3, 5]
            },
            {
                i: 5, t: 4, ranks: [0, 1, 1, 2, 2, 3], n: 6,
                sid: "hierarchical-test-large", reliable_broadcast_enforced: false,
                hd_enabled: false, ids: [0, 1, 2, 3, 4]
            }
        ]
    }
};

// Global state for WASM initialization
let wasmInitialized = false;

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
        formattedMessage = `\n[${timestamp}] 🔄 ${message}\n${'='.repeat(60)}`;
    } else if (type === "round") {
        formattedMessage = `[${timestamp}] 📍 ${message}`;
    } else if (type === "info") {
        formattedMessage = `[${timestamp}] ℹ️  ${message}`;
    } else if (type === "warning") {
        formattedMessage = `[${timestamp}] ⚠️  ${message}`;
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
        } else if (progress >= 75) {
            progressBar.style.backgroundColor = '#17a2b8'; // Info blue
        } else if (progress >= 50) {
            progressBar.style.backgroundColor = '#ffc107'; // Warning yellow
        } else {
            progressBar.style.backgroundColor = '#6c757d'; // Secondary gray
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

// Initialize protocol instances for all parties
const initProtocols = async (partyConfig) => {
    const protocols = [];
    for (let i = 0; i < partyConfig.length; i++) {
        const party = { ...partyConfig[i] };
        try {
            log(`Initializing hierarchical threshold protocol for party ${i} (rank: ${party.ranks[i]})...`, "info");
            const protocol = new StatefulHierarchicalThresholdKeygenProtocol(party);
            protocols.push(protocol);
            log(`Party ${i} protocol initialized successfully`, "success");
        } catch (error) {
            log(`Failed to create protocol for party ${i}: ${error.message}`, "error");
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

const createUnicastMap = (unicastMessages, partyConfig) => {
    const map = {};
    
    // Initialize map with empty arrays for each party
    partyConfig.forEach((_, idx) => {
        map[idx] = [];
    });
    
    // Route unicast messages to recipients
    unicastMessages.forEach((partyMessages, senderIdx) => {
        if (Array.isArray(partyMessages)) {
            log(`Processing ${partyMessages.length} unicast messages from party ${senderIdx}`, "info");
            partyMessages.forEach((unicastMsg, msgIdx) => {
                // Handle both tuple format [recipient, message] and object format {recipient, msg}
                // The Rust function round2_get_unicast_messages returns Vec<(u16, MsgRound2Uni<E>)>
                // which becomes arrays in JavaScript: [recipient_index, message]
                const recipientIdx = Array.isArray(unicastMsg) ? unicastMsg[0] : unicastMsg.recipient;
                const message = Array.isArray(unicastMsg) ? unicastMsg[1] : unicastMsg.msg;
                
                log(`Message ${msgIdx}: sender=${senderIdx}, recipient=${recipientIdx}, format=${Array.isArray(unicastMsg) ? 'tuple' : 'object'}`, "info");
                
                if (map[recipientIdx] !== undefined) {
                    map[recipientIdx].push(message);
                } else {
                    log(`Warning: Invalid recipient index ${recipientIdx} for message from party ${senderIdx}`, "warning");
                }
            });
        }
    });
    
    // Log final routing results
    Object.keys(map).forEach(partyIdx => {
        log(`Party ${partyIdx} will receive ${map[partyIdx].length} sigma shares`, "info");
    });
    
    return map;
};

// Validate hierarchical threshold configuration
const validateConfiguration = (partyConfig) => {
    log("Validating hierarchical threshold configuration...", "info");
    
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
    const sortedRanks = [...ranks].sort((a, b) => a - b);
    let validSets = 0;
    
    // Example validation: ensure there are valid authorized sets
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
            }
        }
    }
    
    if (validSets === 0) {
        throw new Error("No valid authorized sets found for the given rank configuration");
    }
    
    log(`Configuration validated: t=${t}, n=${n}, valid authorized sets=${validSets}`, "success");
    log(`Rank distribution: ${ranks.map((r, i) => `Party${i}:${r}`).join(', ')}`, "info");
    
    return { t, n, ranks, validSets };
};

// Protocol round functions
const runRound1 = (protocols, partyConfig) => {
    updateProgressBar("Round 1", 10, "Generating commitments...");
    log("Running Round 1: Generate commitments", "round");
    
    return protocols.map((protocol, idx) => {
        try {
            const commitment = protocol.round1_generate_commitment();
            log(`Party ${idx} (rank ${partyConfig[idx].ranks[idx]}) generated commitment successfully`, "info");
            return commitment;
        } catch (error) {
            log(`Party ${idx} failed in round 1: ${error.message}`, "error");
            throw error;
        }
    });
};

const setRound1Commitments = (protocols, commitments, partyConfig) => {
    updateProgressBar("Round 1", 20, "Setting commitments for all parties...");
    log("Setting Round 1 commitments for all parties", "info");
    
    const commitmentsMap = createRecipientMap(commitments, partyConfig);
    
    protocols.forEach((protocol, idx) => {
        try {
            protocol.set_round1_commitments({
                commitments: commitmentsMap[idx],
                ids: partyConfig[idx].ids
            });
            log(`Party ${idx} set ${commitmentsMap[idx].length} round 1 commitments`, "info");
        } catch (error) {
            log(`Party ${idx} failed setting round 1 commitments: ${error.message}`, "error");
            throw error;
        }
    });
};

const createReliabilityChecks = (protocols, partyConfig) => {
    updateProgressBar("Round 1", 25, "Creating reliability checks...");
    log("Creating reliability checks (if enforced)", "round");
    
    return protocols.map((protocol, idx) => {
        try {
            if (partyConfig[idx].reliable_broadcast_enforced) {
                const reliabilityCheck = protocol.create_reliability_check();
                log(`Party ${idx} created reliability check`, "info");
                return reliabilityCheck;
            } else {
                log(`Party ${idx} skipping reliability check (not enforced)`, "info");
                return null;
            }
        } catch (error) {
            log(`Party ${idx} failed creating reliability check: ${error.message}`, "error");
            throw error;
        }
    });
};

const runRound2 = (protocols, partyConfig) => {
    updateProgressBar("Round 2", 40, "Generating decommitments and shares...");
    log("Running Round 2: Generate decommitments and unicast messages", "round");
    
    const decommitments = protocols.map((protocol, idx) => {
        try {
            const decommitment = protocol.round2_get_decommitment();
            log(`Party ${idx} generated decommitment successfully`, "info");
            return decommitment;
        } catch (error) {
            log(`Party ${idx} failed getting round 2 decommitment: ${error.message}`, "error");
            throw error;
        }
    });
    
    const unicastMessages = protocols.map((protocol, idx) => {
        try {
            const messages = protocol.round2_get_unicast_messages();
            log(`Party ${idx} generated ${messages.length} unicast messages`, "info");
            return messages;
        } catch (error) {
            log(`Party ${idx} failed getting round 2 unicast messages: ${error.message}`, "error");
            throw error;
        }
    });
    
    return { decommitments, unicastMessages };
};

const setRound2Data = (protocols, decommitments, unicastMessages, partyConfig) => {
    updateProgressBar("Round 2", 60, "Setting decommitments and sigma shares...");
    log("Setting Round 2 data for all parties", "info");
    
    const decommitmentsMap = createRecipientMap(decommitments, partyConfig);
    const sigmasMap = createUnicastMap(unicastMessages, partyConfig);
    
    protocols.forEach((protocol, idx) => {
        try {
            // Set decommitments
            protocol.set_round2_decommitments({
                decommitments: decommitmentsMap[idx],
                ids: partyConfig[idx].ids
            });
            log(`Party ${idx} set ${decommitmentsMap[idx].length} round 2 decommitments`, "info");
            
            // Set sigma shares
            protocol.set_round2_sigmas({
                sigmas: sigmasMap[idx],
                ids: partyConfig[idx].ids
            });
            log(`Party ${idx} set ${sigmasMap[idx].length} round 2 sigma shares`, "info");
            
        } catch (error) {
            log(`Party ${idx} failed setting round 2 data: ${error.message}`, "error");
            throw error;
        }
    });
};

const validateRound2AndPrepareRound3 = (protocols) => {
    updateProgressBar("Round 2", 70, "Validating round 2 data...");
    log("Validating Round 2 data and preparing for Round 3", "round");
    
    protocols.forEach((protocol, idx) => {
        try {
            protocol.validate_round2_and_prepare_round3();
            log(`Party ${idx} validated round 2 data successfully`, "info");
        } catch (error) {
            log(`Party ${idx} failed validating round 2 data: ${error.message}`, "error");
            throw error;
        }
    });
};

const runRound3 = (protocols, partyConfig) => {
    updateProgressBar("Round 3", 80, "Generating Schnorr proofs...");
    log("Running Round 3: Generate Schnorr proofs", "round");
    
    return protocols.map((protocol, idx) => {
        try {
            const proof = protocol.round3_generate_proof();
            log(`Party ${idx} generated Schnorr proof successfully`, "info");
            return proof;
        } catch (error) {
            log(`Party ${idx} failed generating round 3 proof: ${error.message}`, "error");
            throw error;
        }
    });
};

const setRound3Proofs = (protocols, schnorrProofs, partyConfig) => {
    updateProgressBar("Round 3", 90, "Setting Schnorr proofs...");
    log("Setting Round 3 Schnorr proofs for all parties", "info");
    
    const proofsMap = createRecipientMap(schnorrProofs, partyConfig);
    
    protocols.forEach((protocol, idx) => {
        try {
            protocol.set_round3_schnorr_proofs({
                sch_proof: proofsMap[idx],
                ids: partyConfig[idx].ids
            });
            log(`Party ${idx} set ${proofsMap[idx].length} round 3 Schnorr proofs`, "info");
        } catch (error) {
            log(`Party ${idx} failed setting round 3 proofs: ${error.message}`, "error");
            throw error;
        }
    });
};

const finalizeKeyGeneration = (protocols) => {
    updateProgressBar("Finalization", 95, "Generating final key shares...");
    log("Finalizing hierarchical threshold key generation", "round");
    
    return protocols.map((protocol, idx) => {
        try {
            const keyShare = protocol.finalize_key_generation();
            log(`Party ${idx} generated hierarchical threshold key share successfully`, "success");
            return keyShare;
        } catch (error) {
            log(`Party ${idx} failed finalizing key generation: ${error.message}`, "error");
            throw error;
        }
    });
};

// Main test function
async function runTest(configName = 'medium') {
    try {
        log("Initializing WASM module...", "phase");
        await initializeWasm();

        const config = testConfigurations[configName];
        if (!config) {
            throw new Error(`Unknown configuration: ${configName}`);
        }

        log(`Testing Hierarchical Threshold Key Generation`, "phase");
        log(`Configuration: ${config.description}`, "info");
        
        const partyConfig = config.parties;
        
        // Validate configuration
        const validationResult = validateConfiguration(partyConfig);
        updateProgressBar("Initialization", 5, "Configuration validated");

        // Initialize protocols
        log("Initializing protocols for all parties", "round");
        const protocols = await initProtocols(partyConfig);
        updateProgressBar("Initialization", 8, "Protocols initialized");

        // Round 1: Generate commitments
        const commitments = runRound1(protocols, partyConfig);
        setRound1Commitments(protocols, commitments, partyConfig);
        
        // Create reliability checks if enforced
        const reliabilityChecks = createReliabilityChecks(protocols, partyConfig);

        // Round 2: Decommitments and shares
        const { decommitments, unicastMessages } = runRound2(protocols, partyConfig);
        setRound2Data(protocols, decommitments, unicastMessages, partyConfig);
        validateRound2AndPrepareRound3(protocols);

        // Round 3: Schnorr proofs
        const schnorrProofs = runRound3(protocols, partyConfig);
        setRound3Proofs(protocols, schnorrProofs, partyConfig);

        // Finalize and generate key shares
        const keyShares = finalizeKeyGeneration(protocols);
        
        updateProgressBar("Complete", 100, "Hierarchical threshold key generation completed!");
        
        // Validate key shares
        log("Validating generated key shares...", "round");
        keyShares.forEach((keyShare, idx) => {
            if (keyShare && typeof keyShare === 'object') {
                log(`Party ${idx}: Key share generated with rank ${partyConfig[idx].ranks[idx]}`, "success");
            } else {
                throw new Error(`Invalid key share for party ${idx}`);
            }
        });

        log(`Hierarchical threshold key generation completed successfully!`, "phase");
        log(`Generated ${keyShares.length} hierarchical threshold key shares`, "success");
        log(`Configuration: ${validationResult.t}-of-${validationResult.n} threshold with ${validationResult.validSets} valid authorized sets`, "info");
        
        return {
            config: validationResult,
            commitments,
            reliabilityChecks,
            decommitments,
            unicastMessages,
            schnorrProofs,
            keyShares
        };
        
    } catch (error) {
        log(`Test failed with error: ${error.message}`, "error");
        if (error.stack) {
            log(`Stack trace: ${error.stack}`, "error");
        }
        updateProgressBar("Error", 0, "Test failed");
        throw error;
    }
}

// Run all test configurations
async function runAllTests() {
    log("Running all hierarchical threshold test configurations", "phase");
    
    const results = {};
    const configs = Object.keys(testConfigurations);
    
    for (let i = 0; i < configs.length; i++) {
        const configName = configs[i];
        try {
            log(`Running test configuration: ${configName}`, "phase");
            results[configName] = await runTest(configName);
            log(`Configuration ${configName} completed successfully`, "success");
        } catch (error) {
            log(`Configuration ${configName} failed: ${error.message}`, "error");
            results[configName] = { error: error.message };
        }
        
        // Add small delay between tests
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    return results;
}

// For browser environment
if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
        const testButton = document.getElementById('testButton');
        const testAllButton = document.getElementById('testAllButton');
        const clearButton = document.getElementById('clearButton');
        const configSelect = document.getElementById('configSelect');
        
        if (testButton) {
            testButton.addEventListener('click', () => {
                const configName = configSelect ? configSelect.value : 'medium';
                runTest(configName).catch(error => {
                    log(`Test execution failed: ${error.message}`, "error");
                });
            });
        }
        
        if (testAllButton) {
            testAllButton.addEventListener('click', () => {
                runAllTests().catch(error => {
                    log(`Test suite execution failed: ${error.message}`, "error");
                });
            });
        }
        
        if (clearButton) {
            clearButton.addEventListener('click', () => {
                const output = document.getElementById('output');
                if (output) {
                    output.textContent = 'Ready to run hierarchical threshold key generation test...\n';
                }
                updateProgressBar("Ready", 0, "Select configuration and click Run Test");
            });
        }
    });
}

// Debug function to test unicast message format
const debugUnicastMessageFormat = async () => {
    await initializeWasm();
    
    const testParty = {
        i: 0,
        t: 2,
        ranks: [0, 1, 1],
        n: 3,
        sid: "test-debug",
        reliable_broadcast_enforced: false,
        hd_enabled: false,
        ids: [1, 2]
    };
    
    try {
        const protocol = new StatefulHierarchicalThresholdKeygenProtocol(testParty);
        
        // Generate round 1 commitment to set up state
        protocol.round1_generate_commitment();
        
        // Get unicast messages to check their format
        const messages = protocol.round2_get_unicast_messages();
        
        log(`Debug: Unicast messages format check:`, "info");
        log(`Number of messages: ${messages.length}`, "info");
        
        if (messages.length > 0) {
            const firstMsg = messages[0];
            log(`First message type: ${typeof firstMsg}`, "info");
            log(`First message is array: ${Array.isArray(firstMsg)}`, "info");
            
            if (Array.isArray(firstMsg)) {
                log(`Tuple format: [${firstMsg[0]}, ${typeof firstMsg[1]}]`, "info");
            } else {
                log(`Object properties: ${Object.keys(firstMsg).join(', ')}`, "info");
            }
        }
        
        return messages;
    } catch (error) {
        log(`Debug test failed: ${error.message}`, "error");
        throw error;
    }
};

// Export the debug function
if (typeof module !== 'undefined') {
    module.exports = { 
        runTest, 
        runAllTests, 
        testConfigurations,
        validateConfiguration,
        debugUnicastMessageFormat
    };
} else {
    // Make it available globally for browser debugging
    window.debugUnicastMessageFormat = debugUnicastMessageFormat;
}

// Export for ES6 modules (browser)
export { 
    runTest, 
    runAllTests, 
    testConfigurations,
    validateConfiguration,
    debugUnicastMessageFormat
}; 
