use cggmp21_keygen::threshold_stateful::KeygenProtocol as RustKeygenProtocol;
use cggmp21_keygen::execution_id::ExecutionId;
use cggmp21_keygen::security_level::SecurityLevel128;
use cggmp21_keygen::threshold::{MsgRound1, MsgRound2Broad, MsgRound2Uni, MsgRound3};
use generic_ec::curves::Secp256k1;
use rand_dev::DevRng;
use sha2::Sha256;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
/// WASM wrapper for KeygenProtocol
#[wasm_bindgen]
pub struct StatefulKeygenProtocol {
    inner: RustKeygenProtocol<Secp256k1, DevRng, SecurityLevel128, Sha256>,
}

/// Parameters for creating a new KeygenProtocol instance
#[derive(Serialize, Deserialize)]
pub struct KeygenProtocolParams {
    pub i: u16,
    pub t: u16,
    pub n: u16,
    pub sid: String,
    pub reliable_broadcast_enforced: bool,
    #[cfg(feature = "hd-wallet")]
    pub hd_enabled: bool,
}


#[derive(Serialize, Deserialize)]
pub struct Round1Store {
    pub commitments: Vec<MsgRound1<Sha256>>,
    pub ids: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct Round2Store{
    pub decommitments: Vec<MsgRound2Broad<Secp256k1, SecurityLevel128>>,
    pub ids: Vec<u64>,
}

pub enum CurveWrapper {}

#[derive(Serialize, Deserialize)]
pub struct Round2StoreUni{
    pub sigmas: Vec<MsgRound2Uni<Secp256k1>>,
    pub ids: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct Round3Store{
    pub sch_proof: Vec<MsgRound3<Secp256k1>>,
    pub ids: Vec<u64>,
}



#[wasm_bindgen]
impl StatefulKeygenProtocol {
    #[wasm_bindgen(constructor)]
    pub fn new(params: JsValue) -> Result<StatefulKeygenProtocol, JsValue> {
        // Parse parameters from JavaScript
        let params: KeygenProtocolParams = serde_wasm_bindgen::from_value(params)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse KeygenProtocolParams: {}", e)))?;
        
        // Create a static ExecutionId from the provided sid
        let sid_static = ExecutionId::new_static(params.sid.as_bytes());
        
        // Initialize DevRng for WASM
        let rng = DevRng::new();
        
        // Create the Rust KeygenProtocol instance
        let inner = RustKeygenProtocol::new(
            params.i, 
            params.t, 
            params.n, 
            sid_static, 
            params.reliable_broadcast_enforced,
            rng,
            #[cfg(feature = "hd-wallet")]
            params.hd_enabled,
        )
        .map_err(|e| JsValue::from_str(&format!("Invalid parameters for KeygenProtocol: {:?}", e)))?;
        
        Ok(StatefulKeygenProtocol { inner })
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

    pub fn round2_uni(&mut self) -> Result<JsValue, JsValue> {
        let messages = self.inner.run_round_2_uni()
            .map_err(|e| JsValue::from_str(&format!("Failed to run Round 2 uni: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&messages)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 2 uni messages: {}", e)))
    }

    pub fn round2_broad(&mut self) -> Result<JsValue, JsValue> {
        let message = self.inner.run_round_2_broad()
            .map_err(|e| JsValue::from_str(&format!("Failed to run Round 2 broad: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&message)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 2 broad message: {}", e)))
    }


    pub fn set_commitments_from_r1_store(&mut self, commitments: JsValue) -> Result<(), JsValue> {
        let commitments: Round1Store= serde_wasm_bindgen::from_value(commitments)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 1 messages: {}", e)))?;
        
        self.inner.set_commitments_from_r1_store(commitments.commitments, commitments.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set commitments from R1 store: {:?}", e)))?;
        Ok(())
    }

    pub fn set_decommitments_from_r2_store(&mut self, decommitments: JsValue) -> Result<(), JsValue> {
        let decommitments: Round2Store = serde_wasm_bindgen::from_value(decommitments)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 2 decommitments: {}", e)))?;
        
        self.inner.set_decommitments_from_r2_store(decommitments.decommitments, decommitments.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set decommitments from R2 store: {:?}", e)))?;
        Ok(())
    }

    
    pub fn set_sigmas_from_r2_store(&mut self, sigmas: JsValue) -> Result<(), JsValue> {
        let sigmas: Round2StoreUni = serde_wasm_bindgen::from_value(sigmas)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 2 sigmas: {}", e)))?;
        
        self.inner.set_sigmas_from_r2_store(sigmas.sigmas, sigmas.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set sigmas from R2 store: {:?}", e)))?;
        Ok(())
    }

    pub fn round3(&mut self, commitments: JsValue, decommitments: JsValue, sigmas: JsValue) -> Result<JsValue, JsValue> {
        self.set_commitments_from_r1_store(commitments)?;
        self.set_decommitments_from_r2_store(decommitments)?;
        self.set_sigmas_from_r2_store(sigmas)?;

        let message = self.inner.run_round_3()
            .map_err(|e| JsValue::from_str(&format!("Failed to run Round 3: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&message)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round 3 message: {}", e)))
    }

    pub fn set_commitments_from_r3_store(&mut self, schnorrs: JsValue) -> Result<(), JsValue> {
        let schnorrs: Round3Store = serde_wasm_bindgen::from_value(schnorrs)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Round 3 commitments: {}", e)))?;
        
        self.inner.set_commitments_from_r3_store(schnorrs.sch_proof, schnorrs.ids)
            .map_err(|e| JsValue::from_str(&format!("Failed to set commitments from R3 store: {:?}", e)))?;
        Ok(())
    }
    

    pub fn round_key_share(&mut self, commitments: JsValue, decommitments: JsValue, sigmas: JsValue, schnorrs: JsValue) -> Result<JsValue, JsValue> {
        self.set_commitments_from_r1_store(commitments)?;
        self.set_decommitments_from_r2_store(decommitments)?;
        self.set_sigmas_from_r2_store(sigmas)?;
        self.set_commitments_from_r3_store(schnorrs)?;

        let message = self.inner.run_round_key_share()
            .map_err(|e| JsValue::from_str(&format!("Failed to run Round key share: {:?}", e)))?;
        
        serde_wasm_bindgen::to_value(&message)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round key share message: {}", e)))
    }
} 
