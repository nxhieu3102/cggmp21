const WebSocket = require('ws');
const http = require('http');

// Configuration
const CONFIG = {
    PORT: process.env.PORT || 8080,
    MAX_PARTIES: 3,
    PROTOCOL_TIMEOUT: 60000, // 1 minute timeout for each phase
    LOG_LEVEL: process.env.LOG_LEVEL || 'info'
};

// Server state management
class DemoServer {
    constructor() {
        this.clients = new Map(); // WebSocket -> client info
        this.sessions = new Map(); // sessionId -> session info
        this.protocolState = new Map(); // sessionId -> protocol state
        this.messageBuffer = new Map(); // phase-round -> messages
    }

    // Client management
    addClient(ws, clientInfo) {
        this.clients.set(ws, clientInfo);
        this.log(`Client ${clientInfo.partyId} connected from ${clientInfo.ip}`, 'info');
        
        // Join or create session
        this.joinSession(clientInfo.sessionId, clientInfo.partyId, ws);
    }

    // Session management
    joinSession(sessionId, partyId, ws) {
        if (!this.sessions.has(sessionId)) {
            this.sessions.set(sessionId, {
                id: sessionId,
                parties: new Map(),
                createdAt: new Date(),
                currentPhase: 'waiting',
                phaseHistory: []
            });
            
            this.protocolState.set(sessionId, {
                keygen: { completed: false, results: null },
                auxgen: { completed: false, results: null },
                signing: { completed: false, results: null }
            });
            
            this.log(`Created new session: ${sessionId}`, 'info');
        }

        const session = this.sessions.get(sessionId);
        session.parties.set(partyId, {
            id: partyId,
            ws: ws,
            joinedAt: new Date(),
            ready: false
        });

        // Notify other parties
        this.broadcastToSession(sessionId, {
            type: 'party_joined',
            partyId: partyId,
            totalParties: session.parties.size,
            timestamp: new Date().toISOString()
        }, ws);

        this.log(`Party ${partyId} joined session ${sessionId} (${session.parties.size}/${CONFIG.MAX_PARTIES})`, 'info');
    }

    removeClient(ws) {
        const clientInfo = this.clients.get(ws);
        if (clientInfo) {
            this.log(`Client ${clientInfo.partyId} disconnected`, 'info');
            
            // Leave session
            this.leaveSession(clientInfo.sessionId, clientInfo.partyId);
            
            // Notify other parties
            this.broadcastToSession(clientInfo.sessionId, {
                type: 'party_left',
                partyId: clientInfo.partyId,
                timestamp: new Date().toISOString()
            }, ws);
        }
        this.clients.delete(ws);
    }

    leaveSession(sessionId, partyId) {
        const session = this.sessions.get(sessionId);
        if (session && session.parties.has(partyId)) {
            session.parties.delete(partyId);
            
            // Clean up empty sessions
            if (session.parties.size === 0) {
                this.sessions.delete(sessionId);
                this.protocolState.delete(sessionId);
                this.log(`Deleted empty session: ${sessionId}`, 'info');
            }
        }
    }

    // Message handling
    handleMessage(ws, message) {
        const clientInfo = this.clients.get(ws);
        if (!clientInfo) {
            this.log('Received message from unidentified client', 'warning');
            return;
        }

        try {
            switch (message.type) {
                case 'identification':
                    this.handleIdentification(ws, message);
                    break;
                    
                case 'protocol_message':
                    this.handleProtocolMessage(ws, message);
                    break;
                    
                case 'phase_sync':
                    this.handlePhaseSync(ws, message);
                    break;
                    
                case 'ready_check':
                    this.handleReadyCheck(ws, message);
                    break;
                    
                default:
                    this.log(`Unknown message type: ${message.type}`, 'warning');
            }
        } catch (error) {
            this.log(`Error handling message: ${error.message}`, 'error');
            this.sendError(ws, 'Message handling error', error.message);
        }
    }

    handleIdentification(ws, message) {
        for (const [_ws, clientInfo] of this.clients.entries()) {
            console.log(message.partyId, clientInfo.partyId);
            if (clientInfo.partyId === message.partyId) {
                this.log(`Party ${clientInfo.partyId} already connected`, 'warning');
                this.send(ws, {
                    type: 'system',
                    event: 'already_connected',
                    message: `Party ${message.partyId} already connected`,
                    sessionId: message.sessionId
                });
                return;
            }
        }

        const clientInfo = this.clients.get(ws);
        if (clientInfo) {
            clientInfo.partyId = message.partyId;
            clientInfo.sessionId = message.sessionId;
            
            // Update client info
            this.clients.set(ws, clientInfo);
            this.sessions.set(message.sessionId, {
                id: message.sessionId,
                parties: new Map(),
                createdAt: new Date(),
                currentPhase: 'waiting',
                phaseHistory: []
            });
            // Send welcome message
            this.send(ws, {
                type: 'system',
                event: 'identified',
                message: `Welcome Party ${message.partyId}`,
                sessionId: message.sessionId
            });
        }
    }

    handleReadyCheck(ws, message) {
        const clientInfo = this.clients.get(ws);
        const session = this.sessions.get(clientInfo.sessionId);
        
        this.log(`Ready check requested by Party ${clientInfo.partyId} for session ${clientInfo.sessionId}`, 'debug');
        
        this.log(`session: ${session}`, 'debug');
        if (!session) return;
        
        const partyStates = Array.from(session.parties.values()).map(party => ({
            id: party.id,
            ready: party.ready,
            currentPhase: party.currentPhase || 'waiting'
        }));
        
        this.send(ws, {
            type: 'ready_status',
            session: {
                id: session.id,
                currentPhase: session.currentPhase,
                totalParties: session.parties.size,
                parties: partyStates
            }
        });
        
        this.log(`Sent ready status to Party ${clientInfo.partyId}: ${partyStates.filter(p => p.ready).length}/${partyStates.length} parties ready`, 'debug');
    }

    handleProtocolMessage(ws, message) {
        const clientInfo = this.clients.get(ws);
        const { phase, round, data, sessionId } = message;
        
        this.log(`Protocol message: ${phase} Round ${round} from Party ${clientInfo.partyId}`, 'debug');
        
        // Broadcast to all other parties in the session
        this.broadcastToSession(sessionId || clientInfo.sessionId, {
            type: 'protocol_message',
            phase: phase,
            round: round,
            sender: clientInfo.partyId,
            data: data,
            timestamp: new Date().toISOString()
        }, ws);
        
        // Track message for phase coordination
        this.trackProtocolMessage(sessionId || clientInfo.sessionId, phase, round, clientInfo.partyId, data);
    }

    handlePhaseSync(ws, message) {
        const clientInfo = this.clients.get(ws);
        const { phase, ready } = message;
        
        this.log(`Party ${clientInfo.partyId} signaled ${ready ? 'ready' : 'not ready'} for ${phase} phase`, 'debug');
        
        const session = this.sessions.get(clientInfo.sessionId);
        if (!session) return;
        
        const party = session.parties.get(clientInfo.partyId);
        if (party) {
            party.ready = ready;
            party.currentPhase = phase;
        }
        
        // Check if all parties are ready for the phase
        const readyParties = Array.from(session.parties.values()).filter(p => p.ready && p.currentPhase === phase);
        
        this.broadcastToSession(clientInfo.sessionId, {
            type: 'phase_sync',
            phase: phase,
            parties: readyParties.map(p => p.id),
            totalReady: readyParties.length,
            totalParties: session.parties.size
        });
        
        this.log(`Phase sync broadcast: ${readyParties.length}/${session.parties.size} parties ready for ${phase}`, 'debug');
        
        if (readyParties.length >= CONFIG.MAX_PARTIES) {
            this.log(`All parties ready for ${phase}, proceeding...`, 'info');
            session.currentPhase = phase;
            session.phaseHistory.push({
                phase: phase,
                startedAt: new Date(),
                parties: readyParties.map(p => p.id)
            });
        }
    }

    

    // Protocol message tracking
    trackProtocolMessage(sessionId, phase, round, senderId, data) {
        const key = `${sessionId}-${phase}-${round}`;
        
        if (!this.messageBuffer.has(key)) {
            this.messageBuffer.set(key, {
                phase,
                round,
                sessionId,
                messages: [],
                startedAt: new Date()
            });
        }
        
        const buffer = this.messageBuffer.get(key);
        buffer.messages.push({
            senderId,
            data,
            receivedAt: new Date()
        });
        
        const session = this.sessions.get(sessionId);
        const expectedMessages = session ? session.parties.size - 1 : CONFIG.MAX_PARTIES - 1; // Excluding the sender
        
        this.log(`Round buffer ${phase}-${round}: ${buffer.messages.length}/${expectedMessages} messages`, 'debug');
        
        // Clean up old message buffers
        this.cleanupOldMessages();
    }

    cleanupOldMessages() {
        const cutoff = new Date(Date.now() - CONFIG.PROTOCOL_TIMEOUT);
        
        for (const [key, buffer] of this.messageBuffer.entries()) {
            if (buffer.startedAt < cutoff) {
                this.messageBuffer.delete(key);
                this.log(`Cleaned up old message buffer: ${key}`, 'debug');
            }
        }
    }

    // Broadcasting
    broadcastToSession(sessionId, message, excludeWs = null) {
        const session = this.sessions.get(sessionId);
        if (!session) return;
        
        let sentCount = 0;
        for (const party of session.parties.values()) {
            if (party.ws !== excludeWs && party.ws.readyState === WebSocket.OPEN) {
                this.send(party.ws, message);
                sentCount++;
            }
        }
        
        if (sentCount > 0) {
            this.log(`Broadcasted ${message.type} to ${sentCount} parties in session ${sessionId}`, 'debug');
        }
    }

    broadcastToAll(message, excludeWs = null) {
        let sentCount = 0;
        for (const [ws, clientInfo] of this.clients.entries()) {
            if (ws !== excludeWs && ws.readyState === WebSocket.OPEN) {
                this.send(ws, message);
                sentCount++;
            }
        }
        
        if (sentCount > 0) {
            this.log(`Broadcasted ${message.type} to ${sentCount} clients`, 'debug');
        }
    }

    // Utility methods
    send(ws, message) {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(message));
        }
    }

    sendError(ws, title, details) {
        this.send(ws, {
            type: 'error',
            error: title,
            details: details,
            timestamp: new Date().toISOString()
        });
    }

    log(message, level = 'info') {
        if (this.shouldLog(level)) {
            const timestamp = new Date().toISOString();
            const prefix = level.toUpperCase().padEnd(5);
            console.log(`[${timestamp}] ${prefix} ${message}`);
        }
    }

    shouldLog(level) {
        const levels = { debug: 0, info: 1, warning: 2, error: 3 };
        const currentLevel = levels[CONFIG.LOG_LEVEL] || 1;
        const messageLevel = levels[level] || 1;
        return messageLevel >= currentLevel;
    }

    // Server statistics
    getStats() {
        return {
            totalClients: this.clients.size,
            totalSessions: this.sessions.size,
            activeSessions: Array.from(this.sessions.values()).map(session => ({
                id: session.id,
                parties: session.parties.size,
                currentPhase: session.currentPhase,
                createdAt: session.createdAt
            })),
            messageBuffers: this.messageBuffer.size
        };
    }
}

// Initialize server
const demoServer = new DemoServer();

// Create HTTP server for basic health check
const httpServer = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    
    if (req.url === '/stats') {
        res.end(JSON.stringify(demoServer.getStats(), null, 2));
    } else {
        res.end(JSON.stringify({
            name: 'CGGMP21 Demo WebSocket Server',
            status: 'running',
            version: '1.0.0',
            endpoints: {
                websocket: 'ws://localhost:' + CONFIG.PORT,
                stats: 'http://localhost:' + CONFIG.PORT + '/stats'
            }
        }, null, 2));
    }
});

// Create WebSocket server
const wss = new WebSocket.Server({ server: httpServer });

// WebSocket connection handling
wss.on('connection', (ws, req) => {
    
    const ip = req.socket.remoteAddress;
    // Initialize client info
    const clientInfo = {
        ip: ip,
        connectedAt: new Date(),
        partyId: null,
        sessionId: null
    };
    
    demoServer.addClient(ws, clientInfo);
    
    // Send welcome message
    // demoServer.send(ws, {
    //     type: 'system',
    //     event: 'welcome',
    //     message: 'Connected to CGGMP21 Demo WebSocket Server',
    //     serverInfo: {
    //         maxParties: CONFIG.MAX_PARTIES,
    //         protocolTimeout: CONFIG.PROTOCOL_TIMEOUT
    //     },
    //     timestamp: new Date().toISOString()
    // });
    
    // Handle incoming messages
    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data.toString());
            demoServer.handleMessage(ws, message);
        } catch (error) {
            demoServer.log(`Error parsing message from client: ${error.message}`, 'error');
            demoServer.sendError(ws, 'Invalid message format', error.message);
        }
    });
    
    // Handle client disconnection
    ws.on('close', () => {
        demoServer.removeClient(ws);
    });
    
    // Handle WebSocket errors
    ws.on('error', (error) => {
        demoServer.log(`WebSocket error: ${error.message}`, 'error');
        demoServer.removeClient(ws);
    });
});

// Start the server
httpServer.listen(CONFIG.PORT, () => {
    demoServer.log(`CGGMP21 Demo Server listening on port ${CONFIG.PORT}`, 'info');
    demoServer.log(`WebSocket endpoint: ws://localhost:${CONFIG.PORT}`, 'info');
    demoServer.log(`HTTP stats endpoint: http://localhost:${CONFIG.PORT}/stats`, 'info');
    demoServer.log(`Maximum parties per session: ${CONFIG.MAX_PARTIES}`, 'info');
});

// Graceful shutdown handling
process.on('SIGINT', () => {
    demoServer.log('Server shutting down gracefully...', 'info');
    
    // Close all WebSocket connections
    for (const [ws] of demoServer.clients) {
        if (ws.readyState === WebSocket.OPEN) {
            demoServer.send(ws, {
                type: 'system',
                event: 'server_shutdown',
                message: 'Server is shutting down'
            });
            ws.close();
        }
    }
    
    // Close the HTTP server
    httpServer.close(() => {
        demoServer.log('Server shut down successfully', 'info');
        process.exit(0);
    });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    demoServer.log(`Uncaught exception: ${error.message}`, 'error');
    console.error(error.stack);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    demoServer.log(`Unhandled rejection at: ${promise} reason: ${reason}`, 'error');
});

// Periodic cleanup of old data
setInterval(() => {
    demoServer.cleanupOldMessages();
}, 60000); // Run every minute

module.exports = { demoServer, CONFIG }; 
