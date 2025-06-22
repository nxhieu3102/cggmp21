# CGGMP21 WebSocket Message Map

## Overview
This document maps all WebSocket message types exchanged between the server and clients in the CGGMP21 web demo.

## 📤 CLIENT → SERVER Messages

### 1. `identification`
**Purpose**: Identify party to server and join session
**Trigger**: Automatic after WebSocket connection
**Handler**: `handleIdentification()`

```javascript
{
  type: 'identification',
  partyId: 0,
  sessionId: 'demo-1234567890',
  sender: 0,
  timestamp: 1234567890
}
```

**Message return:**
```javascript
{
  type: 'system',
  event: 'identified' | 'already_exist_party_id'
}
```

In case event is identified: display connected to server. Notify others party new party connected and update their UI.

In case event is already_exist_party_id: log already exist party_id;

### 2. `protocol_message`
**Purpose**: Send cryptographic protocol messages (keygen/auxgen/signing)
**Trigger**: During protocol execution from Web Worker
**Handler**: `handleProtocolMessage()`

```javascript
{
  type: 'protocol_message',
  phase: 'keygen|auxgen|signing',
  round: 1,
  data: { /* cryptographic data */ },
  sessionId: 'demo-1234567890',
  sender: 0,
  timestamp: 1234567890
}
```

### 3. `phase_sync`
**Purpose**: Signal readiness for protocol phase
**Trigger**: Automatic on connection + manual during protocol
**Handler**: `handlePhaseSync()`

```javascript
{
  type: 'phase_sync',
  phase: 'waiting|keygen|auxgen|signing',
  ready: true,
  sender: 0,
  timestamp: 1234567890
}
```

### 4. `ready_check`
**Purpose**: Request current readiness status of all parties
**Trigger**: Manual button click or automatic after connection
**Handler**: `handleReadyCheck()`

```javascript
{
  type: 'ready_check',
  sender: 0,
  timestamp: 1234567890
}
```

---

## 📥 SERVER → CLIENT Messages

### 1. `system` (Multiple Events)
**Purpose**: System notifications and status updates
**Trigger**: Various server events

#### Event: `welcome`
```javascript
{
  type: 'system',
  event: 'welcome',
  message: 'Connected to CGGMP21 Demo WebSocket Server',
  serverInfo: {
    maxParties: 3,
    protocolTimeout: 60000
  },
  timestamp: '2023-12-01T10:00:00.000Z'
}
```

#### Event: `identified`
```javascript
{
  type: 'system',
  event: 'identified',
  message: 'Welcome Party 0',
  sessionId: 'demo-1234567890'
}
```

#### Event: `already_connected`
```javascript
{
  type: 'system',
  event: 'already_connected',
  message: 'Party 0 already connected',
  sessionId: 'demo-1234567890'
}
```

#### Event: `disconnect`
```javascript
{
  type: 'system',
  event: 'disconnect',
  sender: 1,
  timestamp: '2023-12-01T10:00:00.000Z'
}
```

#### Event: `server_shutdown`
```javascript
{
  type: 'system',
  event: 'server_shutdown',
  message: 'Server is shutting down'
}
```

### 2. `party_joined`
**Purpose**: Notify when a new party joins the session
**Trigger**: When party completes identification

```javascript
{
  type: 'party_joined',
  partyId: 1,
  totalParties: 2,
  timestamp: '2023-12-01T10:00:00.000Z'
}
```

### 3. `party_left`
**Purpose**: Notify when a party leaves the session
**Trigger**: When party disconnects

```javascript
{
  type: 'party_left',
  partyId: 1,
  timestamp: '2023-12-01T10:00:00.000Z'
}
```

### 4. `protocol_message`
**Purpose**: Relay cryptographic messages between parties
**Trigger**: When server receives protocol_message from another party

```javascript
{
  type: 'protocol_message',
  phase: 'keygen|auxgen|signing',
  round: 1,
  sender: 1,
  data: { /* cryptographic data */ },
  timestamp: '2023-12-01T10:00:00.000Z'
}
```

### 5. `phase_sync`
**Purpose**: Broadcast phase readiness status to all parties
**Trigger**: When server receives phase_sync from any party

```javascript
{
  type: 'phase_sync',
  phase: 'waiting',
  parties: [0, 1],
  totalReady: 2,
  totalParties: 3
}
```

### 6. `ready_status`
**Purpose**: Response to ready_check with full session status
**Trigger**: When server receives ready_check request

```javascript
{
  type: 'ready_status',
  session: {
    id: 'demo-1234567890',
    currentPhase: 'waiting',
    totalParties: 3,
    parties: [
      { id: 0, ready: true, currentPhase: 'waiting' },
      { id: 1, ready: true, currentPhase: 'waiting' },
      { id: 2, ready: false, currentPhase: 'waiting' }
    ]
  }
}
```

### 7. `error`
**Purpose**: Error notifications
**Trigger**: When server encounters errors

```javascript
{
  type: 'error',
  error: 'Message handling error',
  details: 'Invalid message format',
  timestamp: '2023-12-01T10:00:00.000Z'
}
```

---

## 🔄 Message Flow Sequences

### 1. Party Connection Sequence
```
Client                          Server
  │                              │
  ├─── WebSocket Connect ────────▶│
  │◀── system(welcome) ───────────┤
  ├─── identification ───────────▶│
  │◀── system(identified) ────────┤
  │◀── party_joined ──────────────┤ (broadcast to others)
  ├─── phase_sync(ready) ────────▶│
  │◀── phase_sync ────────────────┤ (broadcast to all)
  ├─── ready_check ──────────────▶│
  │◀── ready_status ──────────────┤
```

### 2. Protocol Execution Sequence
```
Client A                 Server                 Client B
  │                       │                       │
  ├─── protocol_message ──▶│                       │
  │                       ├─── protocol_message ──▶│
  │                       │                       │
  │                       │◀─── protocol_message ──┤
  │◀─── protocol_message ──┤                       │
```

### 3. Readiness Check Sequence
```
Client                          Server
  │                              │
  ├─── ready_check ──────────────▶│
  │◀── ready_status ──────────────┤
  │                              │
  ├─── phase_sync(ready) ────────▶│
  │◀── phase_sync ────────────────┤ (broadcast to all)
```

---

## 📊 Message Type Summary

| Direction | Message Type | Purpose | Frequency |
|-----------|--------------|---------|-----------|
| C→S | `identification` | Join session | Once per connection |
| C→S | `protocol_message` | Crypto protocol | Multiple per phase |
| C→S | `phase_sync` | Signal readiness | Per phase transition |
| C→S | `ready_check` | Check status | Manual/automatic |
| S→C | `system` | Status updates | Various events |
| S→C | `party_joined` | Party notification | Per new party |
| S→C | `party_left` | Party notification | Per disconnect |
| S→C | `protocol_message` | Relay crypto data | Multiple per phase |
| S→C | `phase_sync` | Broadcast readiness | Per phase signal |
| S→C | `ready_status` | Status response | Per ready_check |
| S→C | `error` | Error notification | On errors |

---

## 🛡️ Security & Validation

### Server-Side Validation
- **Client Identity**: Checks for duplicate party IDs
- **Session Management**: Validates session membership
- **Message Format**: JSON parsing with error handling
- **Connection State**: WebSocket readiness checks

### Client-Side Handling
- **Message Filtering**: Ignores own protocol messages
- **State Synchronization**: Updates UI based on server responses
- **Error Recovery**: Reconnection logic and timeout handling
- **Type Safety**: Switch-case message routing with defaults

---

## 🔍 Debug Information

### Server Debug Logging (npm run debug)
```
[DEBUG] Party 0 signaled ready for waiting phase
[DEBUG] Ready check requested by Party 0 for session demo-123
[DEBUG] Sent ready status to Party 0: 2/3 parties ready
[DEBUG] Phase sync broadcast: 2/3 parties ready for waiting
[DEBUG] Protocol message: keygen Round 1 from Party 0
[DEBUG] Broadcasted protocol_message to 2 parties in session demo-123
```

### Client Console Logging
```
[INFO] Connected to server as Party 0
[INFO] Party 1 joined the session
[INFO] Signaled ready for waiting phase
[INFO] Checking party readiness...
[INFO] Session demo-123: 2/3 parties ready for waiting
[SUCCESS] ✅ Sufficient parties ready! You can start the protocol.
```

This message map provides a complete reference for understanding the WebSocket communication protocol used in the CGGMP21 demo. 
