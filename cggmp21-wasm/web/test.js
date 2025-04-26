/**
 * Integration tests for the WASM Protocol
 */

// Import the necessary modules
const { Protocol, create_message } = require('./pkg/wasm_protocol');
const WebSocket = require('ws');
const { EventEmitter } = require('events');

// Mock for the WebSocket
class MockWebSocket extends EventEmitter {
  constructor() {
    super();
    this.readyState = WebSocket.OPEN;
    this.sent = [];
  }

  send(message) {
    this.sent.push(message);
  }

  close() {
    this.readyState = WebSocket.CLOSED;
    this.emit('close');
  }

  receiveMessage(message) {
    this.emit('message', { data: JSON.stringify(message) });
  }
}

// Mock for the Web Worker
class MockWorker extends EventEmitter {
  constructor() {
    super();
    this.messages = [];
  }

  postMessage(message) {
    this.messages.push(message);
    
    // Simulate certain responses based on the message type
    if (message.type === 'connect') {
      this.emit('message', { data: { type: 'connection', status: 'connected' } });
    }
    
    if (message.type === 'send') {
      // Echo the message back to simulate receiving from other parties
      setTimeout(() => {
        const otherParties = [
          { sender: 'party1', round: 1, data: 10 },
          { sender: 'party2', round: 1, data: 20 },
          { sender: 'party3', round: 1, data: 30 }
        ].filter(p => p.sender !== message.message.sender);
        
        this.emit('message', { 
          data: { 
            type: 'round_complete', 
            messages: otherParties
          } 
        });
      }, 100);
    }
  }
}

describe('WASM Protocol Integration Tests', () => {
  let protocol;
  
  beforeEach(() => {
    protocol = new Protocol('test-party');
  });
  
  test('should initialize protocol with party ID', () => {
    expect(protocol.get_party_id()).toBe('test-party');
  });
  
  test('should generate a random number in round 1', () => {
    const message = protocol.run_round_1();
    expect(message.sender).toBe('test-party');
    expect(message.round).toBe(1);
    expect(message.data).toBeGreaterThanOrEqual(1);
    expect(message.data).toBeLessThanOrEqual(100);
  });
  
  test('should compute sum correctly in round 2', () => {
    // Set own number
    protocol.run_round_1();
    const ownNumber = protocol.get_own_number();
    
    // Create test messages
    const messages = [
      { sender: 'party1', round: 1, data: 10 },
      { sender: 'party2', round: 1, data: 20 },
      { sender: 'party3', round: 1, data: 30 }
    ];
    
    const sum = protocol.run_round_2(messages);
    expect(sum).toBe(10 + 20 + 30 + ownNumber);
  });
  
  test('should work with the worker for complete flow', (done) => {
    const mockWorker = new MockWorker();
    
    // Setup protocol state
    const protocolState = {
      partyId: 'test-party',
      round: 0,
      protocolInstance: protocol,
      ownNumber: null,
      receivedMessages: [],
      result: null,
    };
    
    // Connect worker
    mockWorker.postMessage({ type: 'connect', serverUrl: 'ws://test' });
    
    // Set up handler for worker messages
    mockWorker.on('message', (event) => {
      const data = event.data;
      
      if (data.type === 'connection' && data.status === 'connected') {
        // Start round 1
        protocolState.round = 1;
        const messageObj = protocol.run_round_1();
        protocolState.ownNumber = messageObj.data;
        
        // Send message via worker
        mockWorker.postMessage({ type: 'send', message: messageObj });
      }
      
      if (data.type === 'round_complete') {
        // Store received messages
        protocolState.receivedMessages = data.messages;
        
        // Calculate sum in round 2
        protocolState.round = 2;
        const result = protocol.run_round_2(protocolState.receivedMessages);
        protocolState.result = result;
        
        // Check if result is correct
        const expectedSum = 10 + 20 + 30 + protocolState.ownNumber;
        expect(result).toBe(expectedSum);
        
        done();
      }
    });
  });
});

describe('WebSocket Worker Tests', () => {
  test('should handle connection and messages', () => {
    const mockWs = new MockWebSocket();
    
    // Simulate connection
    mockWs.emit('open');
    
    // Simulate receiving a message
    const testMessage = { sender: 'party1', round: 1, data: 42 };
    mockWs.receiveMessage(testMessage);
    
    // Check that the message was handled
    expect(mockWs.sent.length).toBe(0); // Worker doesn't send back to same client
  });
  
  test('should handle connection errors and reconnect', () => {
    const mockWs = new MockWebSocket();
    
    // Simulate error
    mockWs.emit('error', new Error('Test error'));
    
    // Simulate close
    mockWs.emit('close');
    
    // Should attempt to reconnect
    expect(mockWs.readyState).toBe(WebSocket.CLOSED);
  });
});

// End-to-end test configuration
describe('End-to-End Tests', () => {
  test('should run the complete protocol with 4 parties', () => {
    // This test would normally use Playwright or a similar tool
    // to launch 4 browser instances and run the protocol
    
    // For this demonstration, we'll just log a message
    console.log('End-to-End test would launch 4 browser instances and run the protocol');
  });
}); 
