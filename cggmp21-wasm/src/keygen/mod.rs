use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::cell::RefCell;
use std::collections::HashMap;

// Round messages
mod messages;
pub use messages::*;

// Stateful threshold key generation protocol
mod threshold;
pub use threshold::*;

// // Error types
// #[derive(Serialize, Deserialize)]
// pub struct KeygenError {
//     pub code: u32,
//     pub message: String,
// }

// // Protocol state that is kept between rounds
// #[derive(Serialize, Deserialize)]
// pub struct KeygenState {
//     // Party information
//     pub party_i: u16,
//     pub party_n: u16,
    
//     // Session identifier
//     pub session_id: String,
    
//     // Current round (1, 2, 3, or 4 for finished)
//     pub round: u8,
    
//     // Store the round 1 messages from all parties
//     pub round1_msgs: HashMap<u16, Round1Message>,
    
//     // Store the round 2 messages from all parties
//     pub round2_msgs: HashMap<u16, Round2Message>,
    
//     // Store the round 3 messages from all parties
//     pub round3_msgs: HashMap<u16, Round3Message>,
    
//     // Final key share
//     pub key_share: Option<String>,
// }

// // WASM interface for keygen
// #[wasm_bindgen]
// pub struct KeygenProtocol {
//     state: RefCell<KeygenState>,
// }

// #[wasm_bindgen]
// impl KeygenProtocol {
//     // Initialize the protocol with party information
//     #[wasm_bindgen(constructor)]
//     pub fn new(party_id: u16, num_parties: u16, session_id: String) -> Result<KeygenProtocol, JsValue> {
//         // Set up panic hook
//         console_error_panic_hook::set_once();
        
//         if party_id == 0 || party_id > num_parties {
//             return Err(JsValue::from_str(&format!(
//                 "Invalid party ID: {} (must be between 1 and {})",
//                 party_id, num_parties
//             )));
//         }
        
//         let state = KeygenState {
//             party_i: party_id,
//             party_n: num_parties,
//             session_id,
//             round: 0,
//             round1_msgs: HashMap::new(),
//             round2_msgs: HashMap::new(),
//             round3_msgs: HashMap::new(),
//             key_share: None,
//         };
        
//         Ok(KeygenProtocol {
//             state: RefCell::new(state),
//         })
//     }
    
//     // Get the current state as a serialized JSON string
//     #[wasm_bindgen]
//     pub fn get_state(&self) -> Result<String, JsValue> {
//         let state = self.state.borrow();
//         serde_json::to_string(&*state)
//             .map_err(|e| JsValue::from_str(&format!("Failed to serialize state: {}", e)))
//     }
    
//     // Set the state from a serialized JSON string (useful for WebWorker communication)
//     #[wasm_bindgen]
//     pub fn set_state(&self, state_json: String) -> Result<(), JsValue> {
//         let new_state: KeygenState = serde_json::from_str(&state_json)
//             .map_err(|e| JsValue::from_str(&format!("Failed to deserialize state: {}", e)))?;
        
//         *self.state.borrow_mut() = new_state;
//         Ok(())
//     }
    
//     // Run round 1 of the keygen protocol
//     #[wasm_bindgen]
//     pub fn run_round_1(&self) -> Result<JsValue, JsValue> {
//         let mut state = self.state.borrow_mut();
        
//         // Check that we're in the correct round
//         if state.round != 0 {
//             return Err(JsValue::from_str(&format!(
//                 "Cannot run round 1: currently in round {}", state.round
//             )));
//         }
        
//         // For this simplified version, we'll just create a commitment value
//         // In a real implementation, this would use cryptographic primitives
//         // Create a simulated commitment (random value)

//         let commitment = format!("commitment-{}-{}", state.party_i, js_sys::Math::random());
//         let party_i = state.party_i;
        
//         // Create round 1 message to broadcast
//         let round1_msg = Round1Message {
//             sender: party_i,
//             commitment,
//         };
        
//         // Add our own message to the collection
//         state.round1_msgs.insert(party_i, round1_msg.clone());
        
//         // Update current round
//         state.round = 1;
        
//         // Create outgoing message
//         let outgoing = OutgoingMessage {
//             round: 1,
//             sender: party_i,
//             broadcast: true,
//             message: serde_json::to_string(&round1_msg)
//                 .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?,
//         };
        
//         // Return JsValue
//         serde_wasm_bindgen::to_value(&outgoing)
//             .map_err(|e| JsValue::from_str(&format!("Failed to serialize outgoing message: {}", e)))
//     }
    
//     // Process incoming round 1 messages and run round 2
//     #[wasm_bindgen]
//     pub fn run_round_2(&self, incoming_messages_js: JsValue) -> Result<JsValue, JsValue> {
//         let mut state = self.state.borrow_mut();
        
//         // Check that we're in the correct round
//         if state.round != 1 {
//             return Err(JsValue::from_str(&format!(
//                 "Cannot run round 2: currently in round {}", state.round
//             )));
//         }
        
//         // Parse incoming messages
//         let incoming_messages: Vec<IncomingMessage> = serde_wasm_bindgen::from_value(incoming_messages_js)
//             .map_err(|e| JsValue::from_str(&format!("Failed to deserialize incoming messages: {}", e)))?;
        
//         // Process each incoming message
//         for msg in incoming_messages {
//             if msg.round != 1 {
//                 return Err(JsValue::from_str(&format!(
//                     "Expected round 1 message, got round {}", msg.round
//                 )));
//             }
            
//             let round1_msg: Round1Message = serde_json::from_str(&msg.message)
//                 .map_err(|e| JsValue::from_str(&format!("Failed to parse round 1 message: {}", e)))?;
            
//             // Store the message
//             state.round1_msgs.insert(round1_msg.sender, round1_msg);
//         }
        
//         // Check if we have received messages from all parties
//         if state.round1_msgs.len() < state.party_n as usize {
//             return Err(JsValue::from_str(&format!(
//                 "Not enough round 1 messages: got {}, expected {}",
//                 state.round1_msgs.len(), state.party_n
//             )));
//         }
        
//         // Create simulated public key and commitment
//         let public_key = format!("pk-{}-{}", state.party_i, js_sys::Math::random());
//         let commitment = format!("commit-{}-{}", state.party_i, js_sys::Math::random());
//         let decommitment = format!("decommit-{}-{}", state.party_i, js_sys::Math::random());
//         let party_i = state.party_i;
        
//         // Construct round 2 message
//         let round2_msg = Round2Message {
//             sender: party_i,
//             rid: format!("rid-{}", party_i),
//             X: public_key,
//             sch_commit: commitment,
//             decommit: decommitment,
//         };
        
//         // Store the message
//         state.round2_msgs.insert(party_i, round2_msg.clone());
        
//         // Update current round
//         state.round = 2;
        
//         // Create outgoing message
//         let outgoing = OutgoingMessage {
//             round: 2,
//             sender: party_i,
//             broadcast: true,
//             message: serde_json::to_string(&round2_msg)
//                 .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?,
//         };
        
//         // Return JsValue
//         serde_wasm_bindgen::to_value(&outgoing)
//             .map_err(|e| JsValue::from_str(&format!("Failed to serialize outgoing message: {}", e)))
//     }
    
//     // Process incoming round 2 messages and run round 3
//     #[wasm_bindgen]
//     pub fn run_round_3(&self, incoming_messages_js: JsValue) -> Result<JsValue, JsValue> {
//         let mut state = self.state.borrow_mut();
        
//         // Check that we're in the correct round
//         if state.round != 2 {
//             return Err(JsValue::from_str(&format!(
//                 "Cannot run round 3: currently in round {}", state.round
//             )));
//         }
        
//         // Parse incoming messages
//         let incoming_messages: Vec<IncomingMessage> = serde_wasm_bindgen::from_value(incoming_messages_js)
//             .map_err(|e| JsValue::from_str(&format!("Failed to deserialize incoming messages: {}", e)))?;
        
//         // Process each incoming message
//         for msg in incoming_messages {
//             if msg.round != 2 {
//                 return Err(JsValue::from_str(&format!(
//                     "Expected round 2 message, got round {}", msg.round
//                 )));
//             }
            
//             let round2_msg: Round2Message = serde_json::from_str(&msg.message)
//                 .map_err(|e| JsValue::from_str(&format!("Failed to parse round 2 message: {}", e)))?;
            
//             // Store the message
//             state.round2_msgs.insert(round2_msg.sender, round2_msg);
//         }
        
//         // Check if we have received messages from all parties
//         if state.round2_msgs.len() < state.party_n as usize {
//             return Err(JsValue::from_str(&format!(
//                 "Not enough round 2 messages: got {}, expected {}",
//                 state.round2_msgs.len(), state.party_n
//             )));
//         }
        
//         // Create simulated proof
//         let proof = format!("proof-{}-{}", state.party_i, js_sys::Math::random());
//         let party_i = state.party_i;
        
//         // Create round 3 message
//         let round3_msg = Round3Message {
//             sender: party_i,
//             sch_proof: proof,
//         };
        
//         // Store the message
//         state.round3_msgs.insert(party_i, round3_msg.clone());
        
//         // Update current round
//         state.round = 3;
        
//         // Create outgoing message
//         let outgoing = OutgoingMessage {
//             round: 3,
//             sender: party_i,
//             broadcast: true,
//             message: serde_json::to_string(&round3_msg)
//                 .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?,
//         };
        
//         // Return JsValue
//         serde_wasm_bindgen::to_value(&outgoing)
//             .map_err(|e| JsValue::from_str(&format!("Failed to serialize outgoing message: {}", e)))
//     }
    
//     // Process incoming round 3 messages and finalize keygen
//     #[wasm_bindgen]
//     pub fn finalize(&self, incoming_messages_js: JsValue) -> Result<JsValue, JsValue> {
//         let mut state = self.state.borrow_mut();
        
//         // Check that we're in the correct round
//         if state.round != 3 {
//             return Err(JsValue::from_str(&format!(
//                 "Cannot finalize: currently in round {}", state.round
//             )));
//         }
        
//         // Parse incoming messages
//         let incoming_messages: Vec<IncomingMessage> = serde_wasm_bindgen::from_value(incoming_messages_js)
//             .map_err(|e| JsValue::from_str(&format!("Failed to deserialize incoming messages: {}", e)))?;
        
//         // Process each incoming message
//         for msg in incoming_messages {
//             if msg.round != 3 {
//                 return Err(JsValue::from_str(&format!(
//                     "Expected round 3 message, got round {}", msg.round
//                 )));
//             }
            
//             let round3_msg: Round3Message = serde_json::from_str(&msg.message)
//                 .map_err(|e| JsValue::from_str(&format!("Failed to parse round 3 message: {}", e)))?;
            
//             // Store the message
//             state.round3_msgs.insert(round3_msg.sender, round3_msg);
//         }
        
//         // Check if we have received messages from all parties
//         if state.round3_msgs.len() < state.party_n as usize {
//             return Err(JsValue::from_str(&format!(
//                 "Not enough round 3 messages: got {}, expected {}",
//                 state.round3_msgs.len(), state.party_n
//             )));
//         }
        
//         // Create a simulated key share for demonstration
//         let key_share = format!(
//             r#"{{
//                 "party_index": {},
//                 "threshold": 0,
//                 "n_parties": {},
//                 "public_key": "simulated_public_key_{}",
//                 "secret_share": "simulated_secret_share_{}"
//             }}"#, 
//             state.party_i, state.party_n, state.party_i, state.party_i
//         );
        
//         // Store the key share
//         state.key_share = Some(key_share.clone());
        
//         // Update round to indicate completion
//         state.round = 4;
        
//         // Return the key share
//         Ok(JsValue::from_str(&key_share))
//     }
    
//     // Helper method to get current round
//     #[wasm_bindgen]
//     pub fn get_round(&self) -> u8 {
//         self.state.borrow().round
//     }
    
//     // Helper method to check if keygen is complete
//     #[wasm_bindgen]
//     pub fn is_complete(&self) -> bool {
//         self.state.borrow().round == 4
//     }
// }

// // Helper functions for serialization/deserialization
// #[wasm_bindgen]
// pub fn serialize_messages(messages: Vec<JsValue>) -> Result<JsValue, JsValue> {
//     let messages_vec: Vec<IncomingMessage> = messages.into_iter()
//         .map(|msg| serde_wasm_bindgen::from_value(msg))
//         .collect::<Result<Vec<IncomingMessage>, _>>()
//         .map_err(|e| JsValue::from_str(&format!("Failed to deserialize messages: {}", e)))?;
    
//     serde_wasm_bindgen::to_value(&messages_vec)
//         .map_err(|e| JsValue::from_str(&format!("Failed to serialize messages: {}", e)))
// }

// #[wasm_bindgen]
// pub fn deserialize_messages(messages_js: JsValue) -> Result<Vec<JsValue>, JsValue> {
//     let messages: Vec<IncomingMessage> = serde_wasm_bindgen::from_value(messages_js)
//         .map_err(|e| JsValue::from_str(&format!("Failed to deserialize messages: {}", e)))?;
    
//     let result: Result<Vec<JsValue>, _> = messages.into_iter()
//         .map(|msg| serde_wasm_bindgen::to_value(&msg))
//         .collect();
    
//     result.map_err(|e| JsValue::from_str(&format!("Failed to serialize messages: {}", e)))
// }
