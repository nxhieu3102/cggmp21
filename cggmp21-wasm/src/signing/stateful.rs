use cggmp21::signing::signing_stateful::SigningProtocol as RustSigningProtocol;
use cggmp21::signing::{DataToSign, Signature};
use cggmp21::signing::msg::{MsgRound1a, MsgRound1b, MsgRound2, MsgRound3, MsgRound4};
use cggmp21::{KeyShare, IncompleteKeyShare};
use cggmp21::key_share::AnyKeyShare;
use cggmp21_keygen::execution_id::ExecutionId;
use cggmp21::security_level::SecurityLevel128;
use generic_ec::curves::Secp256k1;
use rand_dev::DevRng;
use sha2::Sha256;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use hex;

/// WASM wrapper for SigningProtocol
#[wasm_bindgen]
pub struct StatefulSigningProtocol {
    inner: RustSigningProtocol<Secp256k1, DevRng, SecurityLevel128, Sha256>,
}

/// Parameters for creating a new SigningProtocol instance
#[derive(Serialize, Deserialize)]
pub struct SigningProtocolParams {
    pub i: u16,
    pub signing_parties: Vec<u16>,
    pub sid: String,
    pub reliable_broadcast_enforced: bool,
    pub message_hex: Option<String>, // Hex-encoded message to sign (None for presignature generation)
    #[serde(default)]
    pub precompute_tables: Option<Vec<paillier_zk::fast_paillier::precomputed_table::PrecomputeTable>>, // Optional precompute tables
    #[serde(default)]
    pub enable_precomputable: Option<bool>, // Whether to enable precompute table usage (defaults to true)
}

/// Structure for round 1a messages
#[derive(Serialize, Deserialize)]
pub struct Round1aStore {
    pub messages: Vec<MsgRound1a<Secp256k1>>,
    pub ids: Vec<u64>,
}

/// Structure for round 1b messages
#[derive(Serialize, Deserialize)]
pub struct Round1bStore {
    pub messages: Vec<MsgRound1b<Secp256k1>>,
    pub ids: Vec<u64>,
}

/// Structure for round 2 messages
#[derive(Serialize, Deserialize)]
pub struct Round2Store {
    pub messages: Vec<MsgRound2<Secp256k1>>,
    pub ids: Vec<u64>,
}

/// Structure for round 3 messages
#[derive(Serialize, Deserialize)]
pub struct Round3Store {
    pub messages: Vec<MsgRound3<Secp256k1>>,
    pub ids: Vec<u64>,
}

/// Structure for round 4 messages
#[derive(Serialize, Deserialize)]
pub struct Round4Store {
    pub messages: Vec<MsgRound4<Secp256k1>>,
    pub ids: Vec<u64>,
}

/// P2P message with recipient
#[derive(Serialize, Deserialize)]
pub struct P2PMessage<T> {
    pub recipient: u16,
    pub message: T,
}

#[wasm_bindgen]
impl StatefulSigningProtocol {
    /// Create a new signing protocol instance
    #[wasm_bindgen(constructor)]
    pub fn new(params: JsValue, key_share: JsValue) -> Result<StatefulSigningProtocol, JsValue> {
        // Parse parameters from JavaScript
        let params: SigningProtocolParams = serde_wasm_bindgen::from_value(params)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse SigningProtocolParams: {}", e)))?;
        
        // Parse key share
        let key_share: KeyShare<Secp256k1, SecurityLevel128> = serde_wasm_bindgen::from_value(key_share)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse KeyShare: {}", e)))?;
        
        // Create a static ExecutionId from the provided sid
        let sid_static = ExecutionId::new_static(params.sid.as_bytes());
        
        // Initialize DevRng for WASM
        let rng = DevRng::new();
        
        // Parse message to sign if provided
        let message_to_sign = if let Some(message_hex) = params.message_hex {
            let message_bytes = hex::decode(&message_hex)
                .map_err(|e| JsValue::from_str(&format!("Failed to decode message hex: {}", e)))?;
            Some(DataToSign::digest::<Sha256>(&message_bytes))
        } else {
            None
        };
        
        // Create the Rust SigningProtocol instance
        let inner = RustSigningProtocol::new(
            params.i,
            params.signing_parties,
            key_share,
            sid_static,
            rng,
            message_to_sign,
            params.reliable_broadcast_enforced,
            None, // additive_shift
            params.precompute_tables, // cached_precompute_tables
            params.enable_precomputable.unwrap_or(true), // enable_precomputable (defaults to true)
        )
        .map_err(|e| JsValue::from_str(&format!("Invalid parameters for SigningProtocol: {:?}", e)))?;
        
        Ok(StatefulSigningProtocol { inner })
    }
    
    /// Generate round 1a message (broadcast)
    pub fn round1a_generate_message(&mut self) -> Result<JsValue, JsValue> {
        let msg = self.inner.round1a_generate_message()
            .map_err(|e| JsValue::from_str(&format!("Failed to generate Round 1a message: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&msg)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 1a message: {}", e)))
    }
    
    /// Set round 1a messages from other parties
    pub fn set_round1a_messages(&mut self, messages: JsValue) -> Result<(), JsValue> {
        let store: Round1aStore = serde_wasm_bindgen::from_value(messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 1a messages: {}", e)))?;
        
        self.inner.set_round1a_messages(store.messages, store.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set Round 1a messages: {:?}", e)))?;
        
        Ok(())
    }
    
    /// Create reliability check message if reliable broadcast is enforced
    pub fn create_reliability_check(&mut self) -> Result<JsValue, JsValue> {
        let reliability_check = self.inner.create_reliability_check()
            .map_err(|e| JsValue::from_str(&format!("Failed to create reliability check: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&reliability_check)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize reliability check message: {}", e)))
    }
    
    /// Generate round 1b messages (P2P)
    pub fn round1b_generate_messages(&mut self) -> Result<JsValue, JsValue> {
        let messages = self.inner.round1b_generate_messages()
            .map_err(|e| JsValue::from_str(&format!("Failed to generate Round 1b messages: {:?}", e)))?;
        
        let p2p_messages: Vec<P2PMessage<MsgRound1b<Secp256k1>>> = messages
            .into_iter()
            .map(|(recipient, message)| P2PMessage { recipient, message })
            .collect();
        
        serde_wasm_bindgen::to_value(&p2p_messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 1b messages: {}", e)))
    }
    
    /// Set round 1b messages from other parties
    pub fn set_round1b_messages(&mut self, messages: JsValue) -> Result<(), JsValue> {
        let store: Round1bStore = serde_wasm_bindgen::from_value(messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 1b messages: {}", e)))?;
        
        self.inner.set_round1b_messages(store.messages, store.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set Round 1b messages: {:?}", e)))?;
        
        Ok(())
    }
    
    /// Validate round 1b proofs
    pub fn validate_round1b_proofs(&mut self) -> Result<(), JsValue> {
        self.inner.validate_round1b_proofs()
            .map_err(|e| JsValue::from_str(&format!("Failed to validate Round 1b proofs: {:?}", e)))
    }
    
    /// Generate round 2 messages (P2P)
    pub fn round2_generate_messages(&mut self) -> Result<JsValue, JsValue> {
        let messages = self.inner.round2_generate_messages()
            .map_err(|e| JsValue::from_str(&format!("Failed to generate Round 2 messages: {:?}", e)))?;
        
        let p2p_messages: Vec<P2PMessage<MsgRound2<Secp256k1>>> = messages
            .into_iter()
            .map(|(recipient, message)| P2PMessage { recipient, message })
            .collect();
        
        serde_wasm_bindgen::to_value(&p2p_messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 2 messages: {}", e)))
    }
    
    /// Set round 2 messages from other parties
    pub fn set_round2_messages(&mut self, messages: JsValue) -> Result<(), JsValue> {
        let store: Round2Store = serde_wasm_bindgen::from_value(messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 2 messages: {}", e)))?;
        
        self.inner.set_round2_messages(store.messages, store.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set Round 2 messages: {:?}", e)))?;
        
        Ok(())
    }
    
    /// Generate round 3 messages (P2P)
    pub fn round3_generate_messages(&mut self) -> Result<JsValue, JsValue> {
        let messages = self.inner.round3_generate_messages()
            .map_err(|e| JsValue::from_str(&format!("Failed to generate Round 3 messages: {:?}", e)))?;
        
        let p2p_messages: Vec<P2PMessage<MsgRound3<Secp256k1>>> = messages
            .into_iter()
            .map(|(recipient, message)| P2PMessage { recipient, message })
            .collect();
        
        serde_wasm_bindgen::to_value(&p2p_messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 3 messages: {}", e)))
    }
    
    /// Set round 3 messages from other parties
    pub fn set_round3_messages(&mut self, messages: JsValue) -> Result<(), JsValue> {
        let store: Round3Store = serde_wasm_bindgen::from_value(messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 3 messages: {}", e)))?;
        
        self.inner.set_round3_messages(store.messages, store.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set Round 3 messages: {:?}", e)))?;
        
        Ok(())
    }
    
    /// Generate presignature from the protocol state
    pub fn generate_presignature(&mut self) -> Result<JsValue, JsValue> {
        let presignature = self.inner.generate_presignature()
            .map_err(|e| JsValue::from_str(&format!("Failed to generate presignature: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&presignature)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize presignature: {}", e)))
    }
    
    /// Generate round 4 message (partial signature) - returns undefined if no message to sign
    pub fn round4_generate_message(&mut self) -> JsValue {
        match self.inner.round4_generate_message() {
            Ok(Some(msg)) => {
                match serde_wasm_bindgen::to_value(&msg) {
                    Ok(js_val) => js_val,
                    Err(_) => JsValue::undefined()
                }
            }
            Ok(None) => JsValue::undefined(),
            Err(_) => JsValue::undefined()
        }
    }
    
    /// Set round 4 messages from other parties
    pub fn set_round4_messages(&mut self, messages: JsValue) -> Result<(), JsValue> {
        let store: Round4Store = serde_wasm_bindgen::from_value(messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 4 messages: {}", e)))?;
        
        self.inner.set_round4_messages(store.messages, store.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set Round 4 messages: {:?}", e)))?;
        
        Ok(())
    }
    
    /// Generate final signature from round 4 results
    pub fn generate_signature(&mut self, my_partial_sig: JsValue) -> Result<JsValue, JsValue> {
        let my_msg: MsgRound4<Secp256k1> = serde_wasm_bindgen::from_value(my_partial_sig)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize my partial signature: {}", e)))?;
        
        let signature = self.inner.generate_signature(my_msg)
            .map_err(|e| JsValue::from_str(&format!("Failed to generate signature: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&signature)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize signature: {}", e)))
    }
    
    /// Verify a signature against a public key and message
    /// Takes signature (JsValue), public_key (hex string), and message (hex string)
    pub fn verify_signature(signature: JsValue, public_key_hex: String, message_hex: String) -> Result<bool, JsValue> {
        // Parse the signature
        let signature: Signature<Secp256k1> = serde_wasm_bindgen::from_value(signature)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize signature: {}", e)))?;
        
        // Parse the public key from hex
        let public_key_bytes = hex::decode(&public_key_hex)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode public key hex: {}", e)))?;
        
        // Deserialize the public key point
        let public_key = generic_ec::Point::<Secp256k1>::from_bytes(&public_key_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse public key: {:?}", e)))?;
        
        // Parse the message from hex
        let message_bytes = hex::decode(&message_hex)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode message hex: {}", e)))?;
        
        // Create DataToSign from the message
        let message_to_sign = DataToSign::digest::<Sha256>(&message_bytes);
        
        // Verify the signature
        match signature.verify(&public_key, &message_to_sign) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Get public key from a key share (helper method for verification)
    pub fn get_public_key_from_keyshare(key_share: JsValue) -> Result<String, JsValue> {
        // Try to parse as complete key share first
        if let Ok(complete_share) = serde_wasm_bindgen::from_value::<KeyShare<Secp256k1, SecurityLevel128>>(key_share.clone()) {
            let public_key = complete_share.shared_public_key();
            let public_key_bytes = public_key.to_bytes(true); // compressed format
            return Ok(hex::encode(public_key_bytes));
        }
        
        // Try to parse as incomplete key share
        if let Ok(incomplete_share) = serde_wasm_bindgen::from_value::<IncompleteKeyShare<Secp256k1>>(key_share) {
            let public_key = incomplete_share.shared_public_key;
            let public_key_bytes = public_key.to_bytes(true); // compressed format
            return Ok(hex::encode(public_key_bytes));
        }
        
        Err(JsValue::from_str("Failed to parse key share to extract public key"))
    }
    
    /// Generate precompute tables for all parties participating in signing
    /// This creates tables dynamically for benchmarking purposes
    pub fn generate_precompute_tables(&self) -> Result<JsValue, JsValue> {
        let tables = self.inner.generate_precompute_tables();
        serde_wasm_bindgen::to_value(&tables)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize precompute tables: {}", e)))
    }
    
    /// Generate precompute table for a specific party
    /// This is useful for on-demand table generation
    pub fn generate_precompute_table_for_party(&self, party_index: u16) -> Result<JsValue, JsValue> {
        let table = self.inner.generate_precompute_table_for_party(party_index)
            .map_err(|e| JsValue::from_str(&format!("Failed to generate precompute table for party {}: {:?}", party_index, e)))?;
        
        serde_wasm_bindgen::to_value(&table)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize precompute table: {}", e)))
    }
    
    /// Set cached precompute tables for the protocol
    /// This allows for using pre-generated tables for better performance
    pub fn set_cached_precompute_tables(&mut self, tables: JsValue) -> Result<(), JsValue> {
        let tables: Vec<paillier_zk::fast_paillier::precomputed_table::PrecomputeTable> = serde_wasm_bindgen::from_value(tables)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize precompute tables: {}", e)))?;
        
        self.inner.set_cached_precompute_tables(tables);
        Ok(())
    }
} 
