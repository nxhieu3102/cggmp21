const WebSocket = require('ws');
const http = require('http');
const express = require('express');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Serve static files
app.use(express.static(__dirname));

// Store connected clients
const clients = new Map();

wss.on('connection', (ws) => {
    const id = Date.now().toString();
    clients.set(id, ws);
    console.log(`Client connected: ${id}`);

    // Broadcast messages to all other clients
    ws.on('message', (message) => {
        console.log(`Received message from ${id}:`, message);
        clients.forEach((client, clientId) => {
            if (clientId !== id && client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    });

    ws.on('close', () => {
        clients.delete(id);
        console.log(`Client disconnected: ${id}`);
    });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`WebSocket server ready at ws://localhost:${PORT}`);
}); 
