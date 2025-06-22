use cggmp21_keygen::hierarchical_threshold_stateful::HierarchicalThresholdKeygenProtocol as RustKeygenProtocol;
use cggmp21_keygen::execution_id::ExecutionId;
use cggmp21_keygen::security_level::SecurityLevel128;
use cggmp21_keygen::hierarchical_threshold::{MsgRound1, MsgRound2Broad, MsgRound2Uni, MsgRound3};
use generic_ec::curves::Secp256k1;
use rand_dev::DevRng;
use sha2::Sha256;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);
}

macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}


/// WASM wrapper for HierarchicalThresholdKeygenProtocol
#[wasm_bindgen]
pub struct StatefulHierarchicalThresholdKeygenProtocol {
    inner: RustKeygenProtocol<Secp256k1, DevRng, SecurityLevel128, Sha256>,
}

/// Parameters for creating a new HierarchicalThresholdKeygenProtocol instance
#[derive(Serialize, Deserialize)]
pub struct HierarchicalThresholdKeygenProtocolParams {
    pub i: u16,
    pub t: u16,
    pub ranks: Vec<u16>,
    pub n: u16,
    pub sid: String,
    pub reliable_broadcast_enforced: bool,
    #[cfg(feature = "hd-wallet")]
    pub hd_enabled: bool,
}

#[derive(Serialize, Deserialize)]
pub struct HierarchicalThresholdRound1Store {
    pub commitments: Vec<MsgRound1<Sha256>>,
    pub ids: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct HierarchicalThresholdRound2Store {
    pub decommitments: Vec<MsgRound2Broad<Secp256k1, SecurityLevel128>>,
    pub ids: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct HierarchicalThresholdRound2StoreUni {
    pub sigmas: Vec<MsgRound2Uni<Secp256k1>>,
    pub ids: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct HierarchicalThresholdRound3Store {
    pub sch_proof: Vec<MsgRound3<Secp256k1>>,
    pub ids: Vec<u64>,
}

#[wasm_bindgen]
impl StatefulHierarchicalThresholdKeygenProtocol {
    #[wasm_bindgen(constructor)]
    pub fn new(params: JsValue) -> Result<StatefulHierarchicalThresholdKeygenProtocol, JsValue> {
        // Parse parameters from JavaScript
        let params: HierarchicalThresholdKeygenProtocolParams = serde_wasm_bindgen::from_value(params)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse HierarchicalThresholdKeygenProtocolParams: {}", e)))?;
        
        // Create a static ExecutionId from the provided sid
        let sid_static = ExecutionId::new_static(params.sid.as_bytes());
        
        // Initialize DevRng for WASM
        let rng = DevRng::new();
        
        // Create the Rust HierarchicalThresholdKeygenProtocol instance
        let inner = RustKeygenProtocol::new(
            params.i, 
            params.t, 
            params.ranks,
            params.n, 
            sid_static, 
            params.reliable_broadcast_enforced,
            rng,
            #[cfg(feature = "hd-wallet")]
            params.hd_enabled,
        )
        .map_err(|e| JsValue::from_str(&format!("Invalid parameters for HierarchicalThresholdKeygenProtocol: {:?}", e)))?;
        
        Ok(StatefulHierarchicalThresholdKeygenProtocol { inner })
    }
    
    /// Generate commitment for Round 1 of the protocol
    pub fn round1_generate_commitment(&mut self) -> Result<JsValue, JsValue> {
        // Call the underlying Rust method
        let msg_round1 = self.inner.round1_generate_commitment()
            .map_err(|e| JsValue::from_str(&format!("Failed to generate Round 1 commitment: {:?}", e)))?;
        
        // Serialize the result for JavaScript
        serde_wasm_bindgen::to_value(&msg_round1)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 1 message: {}", e)))
    }

    /// Set round 1 commitments from other parties
    pub fn set_round1_commitments(&mut self, commitments: JsValue) -> Result<(), JsValue> {
        let commitments: HierarchicalThresholdRound1Store = serde_wasm_bindgen::from_value(commitments)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 1 messages: {}", e)))?;
        
        self.inner.set_round1_commitments(commitments.commitments, commitments.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set commitments from R1 store: {:?}", e)))?;
        Ok(())
    }

    /// Create reliability check message (optional)
    pub fn create_reliability_check(&mut self) -> Result<JsValue, JsValue> {
        let reliability_check = self.inner.create_reliability_check()
            .map_err(|e| JsValue::from_str(&format!("Failed to create reliability check: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&reliability_check)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize reliability check message: {}", e)))
    }

    /// Get decommitment for round 2 broadcast
    pub fn round2_get_decommitment(&self) -> Result<JsValue, JsValue> {
        let message = self.inner.round2_get_decommitment()
            .map_err(|e| JsValue::from_str(&format!("Failed to get Round 2 decommitment: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&message)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 2 decommitment message: {}", e)))
    }

    /// Get unicast messages for round 2
    pub fn round2_get_unicast_messages(&self) -> Result<JsValue, JsValue> {
        let messages = self.inner.round2_get_unicast_messages()
            .map_err(|e| JsValue::from_str(&format!("Failed to get Round 2 unicast messages: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 2 unicast messages: {}", e)))
    }

    /// Set round 2 decommitments from other parties
    pub fn set_round2_decommitments(&mut self, decommitments: JsValue) -> Result<(), JsValue> {
        let decommitments: HierarchicalThresholdRound2Store = serde_wasm_bindgen::from_value(decommitments)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 2 decommitments: {}", e)))?;
        
        self.inner.set_round2_decommitments(decommitments.decommitments, decommitments.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set decommitments from R2 store: {:?}", e)))?;
        Ok(())
    }

    /// Set round 2 sigma shares from other parties
    pub fn set_round2_sigmas(&mut self, sigmas: JsValue) -> Result<(), JsValue> {
        let sigmas: HierarchicalThresholdRound2StoreUni = serde_wasm_bindgen::from_value(sigmas)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 2 sigmas: {}", e)))?;
        
        self.inner.set_round2_sigmas(sigmas.sigmas, sigmas.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set sigmas from R2 store: {:?}", e)))?;
        Ok(())
    }

    /// Validate round 2 data and prepare for round 3
    pub fn validate_round2_and_prepare_round3(&mut self) -> Result<(), JsValue> {
        self.inner.validate_round2_and_prepare_round3()
            .map_err(|e| JsValue::from_str(&format!("Failed to validate round 2 and prepare round 3: {:?}", e)))?;
        Ok(())
    }

    /// Generate Schnorr proof for round 3
    pub fn round3_generate_proof(&mut self) -> Result<JsValue, JsValue> {
        let message = self.inner.round3_generate_proof()
            .map_err(|e| JsValue::from_str(&format!("Failed to generate Round 3 proof: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&message)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 3 message: {}", e)))
    }

    /// Set round 3 Schnorr proofs from other parties
    pub fn set_round3_schnorr_proofs(&mut self, schnorr_proofs: JsValue) -> Result<(), JsValue> {
        let schnorr_proofs: HierarchicalThresholdRound3Store = serde_wasm_bindgen::from_value(schnorr_proofs)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 3 proofs: {}", e)))?;
        
        self.inner.set_round3_schnorr_proofs(schnorr_proofs.sch_proof, schnorr_proofs.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set proofs from R3 store: {:?}", e)))?;
        Ok(())
    }

    /// Finalize key generation and get the key share
    pub fn finalize_key_generation(&mut self) -> Result<JsValue, JsValue> {

        let key_share = self.inner.finalize_key_generation()
            .map_err(|e| {
                console_log!("Failed to finalize key generation: {:?}", e);
                JsValue::from_str(&format!("Failed to finalize key generation: {:?}", e))
            })?;
        
        serde_wasm_bindgen::to_value(&key_share)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize key share: {}", e)))
    }

    /// Complete round 2 (convenience method that combines setting data and validation)
    pub fn complete_round2(&mut self, commitments: JsValue, decommitments: JsValue, sigmas: JsValue) -> Result<(), JsValue> {
        self.set_round1_commitments(commitments)?;
        self.set_round2_decommitments(decommitments)?;
        self.set_round2_sigmas(sigmas)?;
        self.validate_round2_and_prepare_round3()?;
        Ok(())
    }

    /// Complete round 3 and generate key share (convenience method)
    pub fn complete_round3_and_generate_key_share(
        &mut self, 
        commitments: JsValue, 
        decommitments: JsValue, 
        sigmas: JsValue, 
        schnorr_proofs: JsValue
    ) -> Result<JsValue, JsValue> {
        self.set_round1_commitments(commitments)?;
        self.set_round2_decommitments(decommitments)?;
        self.set_round2_sigmas(sigmas)?;
        self.set_round3_schnorr_proofs(schnorr_proofs)?;
        self.validate_round2_and_prepare_round3()?;
        self.finalize_key_generation()
    }

    /// Get the current protocol state for debugging (returns serialized state info)
    pub fn get_protocol_state_info(&self) -> Result<JsValue, JsValue> {
        let state = self.inner.get_state();
        
        // Create a simplified state info object for debugging
        let state_info = serde_json::json!({
            "party_index": state.i,
            "threshold": state.t,
            "ranks": state.ranks,
            "num_parties": state.n,
            "reliable_broadcast_enforced": state.reliable_broadcast_enforced,
            "has_commitment": state.my_commitment.is_some(),
            "has_decommitment": state.my_decommitment.is_some(),
            "has_combined_rid": state.combined_rid.is_some(),
            "has_public_shares": state.all_public_shares_ys.is_some(),
            "has_secret_share": state.my_secret_share_sigma.is_some(),
            "has_schnorr_proof": state.my_schnorr_proof.is_some(),
            "has_final_key_share": state.key_share.is_some(),
        });
        
        serde_wasm_bindgen::to_value(&state_info)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize state info: {}", e)))
    }
} 
