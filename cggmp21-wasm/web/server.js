const WebSocket = require('ws');
const http = require('http');

// Create HTTP server
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('WebSocket Server for WASM Protocol Demo\n');
});

// Set the port for the server to listen on
const PORT = process.env.PORT || 8080;

// Create WebSocket server instance
const wss = new WebSocket.Server({ server });

// Store connected clients with their IDs
const clients = new Map();

// Log server actions
console.log(`Starting WebSocket server on port ${PORT}...`);

// Handle new WebSocket connections
wss.on('connection', (ws, req) => {
  const ip = req.socket.remoteAddress;
  console.log(`New connection from ${ip}`);

  // Assign a temporary ID until client identifies itself
  let clientId = `unidentified-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  clients.set(ws, clientId);

  // Handle messages from clients
  ws.on('message', (message) => {
    try {
      // Convert buffer to string if needed
      const messageStr = message instanceof Buffer ? message.toString() : message.toString();
      const parsedMessage = JSON.parse(messageStr);
      
      // Validate message format
      if (!parsedMessage || !parsedMessage.sender || parsedMessage.round === undefined) {
        console.error('Invalid message format:', parsedMessage);
        return;
      }

      // Update client ID from the first message received
      if (clients.get(ws) !== parsedMessage.sender) {
        const oldId = clients.get(ws);
        clientId = parsedMessage.sender;
        clients.set(ws, clientId);
        console.log(`Client identified: ${oldId} -> ${clientId}`);
      }

      console.log(`Received message from ${clientId}:`, parsedMessage);

      // Broadcast message to all other clients
      broadcastMessage(ws, messageStr);
    } catch (error) {
      console.error('Error processing message:', error.message);
    }
  });

  // Handle client disconnection
  ws.on('close', () => {
    const disconnectedClientId = clients.get(ws);
    console.log(`Client disconnected: ${disconnectedClientId}`);
    clients.delete(ws);
    
    // Notify other clients about the disconnection
    const disconnectMessage = {
      type: 'system',
      event: 'disconnect',
      sender: disconnectedClientId,
      timestamp: new Date().toISOString()
    };
    
    broadcastToAll(JSON.stringify(disconnectMessage));
  });

  // Handle errors
  ws.on('error', (error) => {
    console.error(`Error with client ${clients.get(ws)}:`, error.message);
  });

  // Send a welcome message to the new client
  const welcomeMessage = {
    type: 'system',
    event: 'welcome',
    message: 'Connected to WASM Protocol WebSocket Server',
    timestamp: new Date().toISOString()
  };
  
  ws.send(JSON.stringify(welcomeMessage), { binary: false });
});

// Broadcast a message to all clients except the sender
function broadcastMessage(sender, message) {
  const senderId = clients.get(sender);
  
  wss.clients.forEach((client) => {
    if (client !== sender && client.readyState === WebSocket.OPEN) {
      console.log(`Broadcasting message from ${senderId} to ${clients.get(client)}`);
      client.send(message, { binary: false });
    }
  });
}

// Broadcast a message to all connected clients
function broadcastToAll(message) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message, { binary: false });
    }
  });
}

// Start the server
server.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});

// Handle server shutdown
process.on('SIGINT', () => {
  console.log('Server shutting down...');
  
  // Close all WebSocket connections
  wss.clients.forEach((client) => {
    client.close();
  });
  
  // Close the server
  server.close(() => {
    console.log('Server shut down successfully');
    process.exit(0);
  });
}); 
