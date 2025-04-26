use serde::{Serialize, Deserialize};
use wasm_bindgen::prelude::*;

// Round 1 message structure
#[derive(Serialize, Deserialize, Clone)]
pub struct Round1Message {
    pub sender: u16,
    pub commitment: String, // SerializedHash
}

// Round 2 message structure
#[derive(Serialize, Deserialize, Clone)]
pub struct Round2Message {
    pub sender: u16,
    pub rid: String, // SerializedBytes
    pub X: String, // SerializedPoint
    pub sch_commit: String, // SerializedPoint
    pub decommit: String, // SerializedBytes
}

// Round 3 message structure
#[derive(Serialize, Deserialize, Clone)]
pub struct Round3Message {
    pub sender: u16,
    pub sch_proof: String, // SerializedBytes
}

// Outgoing message wrapper
#[derive(Serialize, Deserialize)]
pub struct OutgoingMessage {
    pub round: u8,
    pub sender: u16,
    pub broadcast: bool,
    pub message: String, // Serialized message data
}

// Incoming message wrapper
#[derive(Serialize, Deserialize)]
pub struct IncomingMessage {
    pub round: u8,
    pub sender: u16,
    pub message: String, // Serialized message data
}

// JavaScript constructors and helpers for message types
#[wasm_bindgen]
pub fn create_round1_message(sender: u16, commitment: String) -> JsValue {
    let msg = Round1Message {
        sender,
        commitment,
    };
    
    serde_wasm_bindgen::to_value(&msg).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn create_round2_message(sender: u16, rid: String, x: String, sch_commit: String, decommit: String) -> JsValue {
    let msg = Round2Message {
        sender,
        rid,
        X: x,
        sch_commit,
        decommit,
    };
    
    serde_wasm_bindgen::to_value(&msg).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn create_round3_message(sender: u16, sch_proof: String) -> JsValue {
    let msg = Round3Message {
        sender,
        sch_proof,
    };
    
    serde_wasm_bindgen::to_value(&msg).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn create_outgoing_message(round: u8, sender: u16, broadcast: bool, message: String) -> JsValue {
    let msg = OutgoingMessage {
        round,
        sender,
        broadcast,
        message,
    };
    
    serde_wasm_bindgen::to_value(&msg).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn create_incoming_message(round: u8, sender: u16, message: String) -> JsValue {
    let msg = IncomingMessage {
        round,
        sender,
        message,
    };
    
    serde_wasm_bindgen::to_value(&msg).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen]
pub fn parse_round1_message(value: JsValue) -> Result<JsValue, JsValue> {
    let msg: Round1Message = serde_wasm_bindgen::from_value(value)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse Round1Message: {}", e)))?;
    
    serde_wasm_bindgen::to_value(&msg)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round1Message: {}", e)))
}

#[wasm_bindgen]
pub fn parse_round2_message(value: JsValue) -> Result<JsValue, JsValue> {
    let msg: Round2Message = serde_wasm_bindgen::from_value(value)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse Round2Message: {}", e)))?;
    
    serde_wasm_bindgen::to_value(&msg)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round2Message: {}", e)))
}

#[wasm_bindgen]
pub fn parse_round3_message(value: JsValue) -> Result<JsValue, JsValue> {
    let msg: Round3Message = serde_wasm_bindgen::from_value(value)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse Round3Message: {}", e)))?;
    
    serde_wasm_bindgen::to_value(&msg)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round3Message: {}", e)))
}

#[wasm_bindgen]
pub fn parse_outgoing_message(value: JsValue) -> Result<JsValue, JsValue> {
    let msg: OutgoingMessage = serde_wasm_bindgen::from_value(value)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse OutgoingMessage: {}", e)))?;
    
    serde_wasm_bindgen::to_value(&msg)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize OutgoingMessage: {}", e)))
}

#[wasm_bindgen]
pub fn parse_incoming_message(value: JsValue) -> Result<JsValue, JsValue> {
    let msg: IncomingMessage = serde_wasm_bindgen::from_value(value)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse IncomingMessage: {}", e)))?;
    
    serde_wasm_bindgen::to_value(&msg)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize IncomingMessage: {}", e)))
} 
