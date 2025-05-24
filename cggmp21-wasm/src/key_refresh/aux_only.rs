use cggmp21::key_refresh::aux_only_stateful::AuxGenProtocol as RustAuxGenProtocol;
use cggmp21_keygen::execution_id::ExecutionId;
use cggmp21::security_level::SecurityLevel128;
use cggmp21::key_refresh::aux_only::{MsgRound1, MsgRound2, MsgRound3, MsgReliabilityCheck};
use cggmp21::key_refresh::PregeneratedPaillierKey;
use sha2::Sha256;
use rand_dev::DevRng;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};

/// WASM wrapper for AuxGenProtocol
#[wasm_bindgen]
pub struct StatefulAuxGenProtocol {
    inner: RustAuxGenProtocol<DevRng, SecurityLevel128, Sha256>,
}

/// Parameters for creating a new AuxGenProtocol instance
#[derive(Serialize, Deserialize)]
pub struct AuxGenProtocolParams {
    pub i: u16,
    pub n: u16,
    pub sid: String,
    pub pregenerated_paillier_key: PregeneratedPaillierKey<SecurityLevel128>,
    pub reliable_broadcast_enforced: bool,
    pub compute_multiexp_table: bool,
    pub compute_crt: bool,
}

/// Structure for round 1 messages
#[derive(Serialize, Deserialize)]
pub struct Round1Store {
    pub commitments: Vec<MsgRound1<Sha256>>,
    pub ids: Vec<u64>,
}

/// Structure for round 2 messages
#[derive(Serialize, Deserialize)]
pub struct Round2Store {
    pub decommitments: Vec<MsgRound2<SecurityLevel128>>,
    pub ids: Vec<u64>,
}

/// Structure for round 3 messages
#[derive(Serialize, Deserialize)]
pub struct Round3Store {
    pub messages: Vec<MsgRound3>,
    pub ids: Vec<u64>,
}

#[wasm_bindgen]
impl StatefulAuxGenProtocol {
    #[wasm_bindgen(constructor)]
    pub async fn new(params: JsValue) -> Result<StatefulAuxGenProtocol, JsValue> {
        // Parse parameters from JavaScript
        let params: AuxGenProtocolParams = serde_wasm_bindgen::from_value(params)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse AuxGenProtocolParams: {}", e)))?;
        
        // Create a static ExecutionId from the provided sid
        let sid_static = ExecutionId::new_static(params.sid.as_bytes());
        
        // Initialize DevRng for WASM
        let rng = DevRng::new();
        let pregenerated_primes = PregeneratedPaillierKey::<SecurityLevel128>::generate::<DevRng>(&mut rng.clone()).unwrap();

        // Create the Rust AuxGenProtocol instance
        let inner = RustAuxGenProtocol::new(
            params.i,
            params.n,
            sid_static,
            rng,
            pregenerated_primes,
            params.reliable_broadcast_enforced,
            params.compute_multiexp_table,
            params.compute_crt,
        )
        .map_err(|e| JsValue::from_str(&format!("Invalid parameters for AuxGenProtocol: {:?}", e)))?;
        
        Ok(StatefulAuxGenProtocol { inner })
    }
    
    /// Generate commitment for Round 1 of the protocol
    pub fn round1_generate_commitment(&mut self) -> Result<JsValue, JsValue> {
        // Call the underlying Rust method
        let commitment = self.inner.round1_generate_commitment()
            .map_err(|e| JsValue::from_str(&format!("Failed to generate Round 1 commitment: {:?}", e)))?;
        
        // Serialize the result for JavaScript
        serde_wasm_bindgen::to_value(&commitment)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 1 message: {}", e)))
    }
    
    /// Set commitments received from other parties in Round 1
    pub fn set_round1_commitments(&mut self, commitments: JsValue) -> Result<(), JsValue> {
        let commitments: Round1Store = serde_wasm_bindgen::from_value(commitments)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 1 commitments: {}", e)))?;
        
        self.inner.set_round1_commitments(commitments.commitments, commitments.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set Round 1 commitments: {:?}", e)))?;
        
        Ok(())
    }
    
    /// Create reliability check message if reliable broadcast is enforced
    pub fn create_reliability_check(&mut self) -> Result<JsValue, JsValue> {
        let reliability_check = self.inner.create_reliability_check()
            .map_err(|e| JsValue::from_str(&format!("Failed to create reliability check: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&reliability_check)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize reliability check message: {}", e)))
    }
    
    /// Get decommitment for Round 2
    pub fn round2_get_decommitment(&self) -> Result<JsValue, JsValue> {
        let decommitment = self.inner.round2_get_decommitment()
            .map_err(|e| JsValue::from_str(&format!("Failed to get Round 2 decommitment: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&decommitment)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 2 decommitment: {}", e)))
    }
    
    /// Set decommitments received from other parties in Round 2
    pub fn set_round2_decommitments(&mut self, decommitments: JsValue) -> Result<(), JsValue> {
        let decommitments: Round2Store = serde_wasm_bindgen::from_value(decommitments)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 2 decommitments: {}", e)))?;
        
        self.inner.set_round2_decommitments(decommitments.decommitments, decommitments.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set Round 2 decommitments: {:?}", e)))?;
        
        Ok(())
    }
    
    /// Validate decommitments and compute combined random bytes
    pub fn validate_round2_decommitments(&mut self) -> Result<(), JsValue> {
        self.inner.validate_round2_decommitments()
            .map_err(|e| JsValue::from_str(&format!("Failed to validate Round 2 decommitments: {:?}", e)))
    }
    
    /// Create messages for Round 3
    pub fn round3_create_messages(&mut self) -> Result<JsValue, JsValue> {
        let messages = self.inner.round3_create_messages()
            .map_err(|e| JsValue::from_str(&format!("Failed to create Round 3 messages: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 3 messages: {}", e)))
    }
    
    /// Set messages received from other parties in Round 3
    pub fn set_round3_messages(&mut self, messages: JsValue) -> Result<(), JsValue> {
        let messages: Round3Store = serde_wasm_bindgen::from_value(messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 3 messages: {}", e)))?;
        
        self.inner.set_round3_messages(messages.messages, messages.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set Round 3 messages: {:?}", e)))?;
        
        Ok(())
    }
    
    /// Validate proofs and generate the final output
    pub fn finalize(&mut self) -> Result<JsValue, JsValue> {
        let aux_info = self.inner.create_aux_info()
            .map_err(|e| JsValue::from_str(&format!("Failed to finalize protocol: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&aux_info)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize auxiliary info: {}", e)))
    }
} 
