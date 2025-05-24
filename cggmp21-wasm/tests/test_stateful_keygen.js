import init, { StatefulKeygenProtocol } from '../pkg/cggmp21_wasm.js';

// Test configuration
const parties = [
    {
        i: 0,
        t: 2,
        n: 3,
        sid: "test-session-123",
        reliable_broadcast_enforced: false,
        ids: [1, 2]
    },
    {
        i: 1,
        t: 2,
        n: 3,
        sid: "test-session-123",
        reliable_broadcast_enforced: false,
        ids: [0, 2]
    },
    {
        i: 2,
        t: 2,
        n: 3,
        sid: "test-session-123",
        reliable_broadcast_enforced: false,
        ids: [0, 1]
    }
];

// Initialize protocol instances for all parties
const initProtocols = (parties) => {
    return parties.map(party => new StatefulKeygenProtocol(party));
};

// Helper functions for message handling
const createRecipientMap = (items, partyConfig) => {
    const map = {};
    items.forEach((item, idx) => {
        map[idx] = items.filter((_, idx2) => partyConfig[idx].ids.includes(idx2));
    });
    return map;
};

const createSigmasMap = (sigmasMsgs) => {
    const map = {};
    sigmasMsgs.forEach(msgs => {
        msgs.forEach(msg => {
            const recipient = msg.recipient.OneParty;
            if (!map[recipient]) {
                map[recipient] = [];
            }
            map[recipient].push(msg.msg.Round2Uni);
        });
    });
    return map;
};

// Protocol round functions
const runRound1 = (protocols) => {
    return protocols.map(protocol => protocol.round1_generate_commitment());
};

const runRound2Broad = (protocols) => {
    return protocols.map(protocol => protocol.round2_broad());
};

const runRound2Uni = (protocols) => {
    return protocols.map(protocol => protocol.round2_uni());
};

const runRound3 = (protocols, commitments, decommitments, sigmasMsgs) => {
    const sigmasMap = createSigmasMap(sigmasMsgs);
    const commitmentsMap = createRecipientMap(commitments, parties);
    const decommitmentsMap = createRecipientMap(decommitments, parties);

    return protocols.map((protocol, idx) => {
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
};

const runRoundKeyShare = (protocols, commitments, decommitments, sigmasMsgs, round3Msgs) => {
    const sigmasMap = createSigmasMap(sigmasMsgs);
    const commitmentsMap = createRecipientMap(commitments, parties);
    const decommitmentsMap = createRecipientMap(decommitments, parties);
    const schProofMap = createRecipientMap(round3Msgs, parties);

    return protocols.map((protocol, idx) => {        
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
};

// Main test function
async function runTest() {
    try {
        console.log("Initializing WASM module...");
        await init();

        console.log("Testing StatefulKeygenProtocol...");

        const protocols = initProtocols(parties);
        
        // Round 1: Generate commitments
        const commitments = runRound1(protocols);
        console.log("Round 1 commitments:", commitments);

        // Round 2: Broadcast decommitments and send sigmas
        const decommitments = runRound2Broad(protocols);
        console.log("Round 2 decommitments:", decommitments);
        
        const sigmasMsgs = runRound2Uni(protocols);
        console.log("Round 2 sigma messages:", sigmasMsgs);

        // Round 3: Generate Schnorr proofs
        const round3Msgs = runRound3(protocols, commitments, decommitments, sigmasMsgs);
        console.log("Round 3 messages:", round3Msgs);

        // Final round: Generate key shares
        const keyShares = runRoundKeyShare(protocols, commitments, decommitments, sigmasMsgs, round3Msgs);
        console.log("Key share messages:", keyShares);

        console.log("Test completed successfully!");
        return keyShares;
    } catch (error) {
        console.error("Test failed with error:", error);
        throw error;
    }
}

// For browser environment
if (typeof document !== 'undefined') {
    document.getElementById('testButton')?.addEventListener('click', () => {
        const outputElement = document.getElementById('output');
        if (outputElement) {
            outputElement.textContent = '';
            runTest().then(result => {
                outputElement.textContent += "Test completed successfully!\n";
            }).catch(error => {
                outputElement.textContent += "Test failed with error: " + error + "\n";
            });
        }
    });
}

// For Node.js or direct script execution
if (typeof module !== 'undefined') {
    module.exports = { runTest };
}
