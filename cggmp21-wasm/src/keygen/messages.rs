// use cggmp21_keygen::security_level::SecurityLevel128;
// use cggmp21_keygen::threshold as threshold_keygen;
// use generic_ec::curves::Secp256k1;
// use rand_dev::{self, DevRng};
// use serde::{Deserialize, Serialize};
// use sha2::Sha256;
// use wasm_bindgen::prelude::*;
// // Round 1 message structure
// #[derive(Serialize, Deserialize, Clone)]
// pub struct Round1Message {
//     pub sender: u16,
//     pub commitment: String, // SerializedHash
// }

// // Round 2 message structure
// #[derive(Serialize, Deserialize, Clone)]
// pub struct Round2Message {
//     pub sender: u16,
//     pub rid: String,        // SerializedBytes
//     pub X: String,          // SerializedPoint
//     pub sch_commit: String, // SerializedPoint
//     pub decommit: String,   // SerializedBytes
// }

// // Round 3 message structure
// #[derive(Serialize, Deserialize, Clone)]
// pub struct Round3Message {
//     pub sender: u16,
//     pub sch_proof: String, // SerializedBytes
// }

// // Outgoing message wrapper
// #[derive(Serialize, Deserialize)]
// pub struct OutgoingMessage {
//     pub round: u8,
//     pub sender: u16,
//     pub broadcast: bool,
//     pub message: String, // Serialized message data
// }

// // Incoming message wrapper
// #[derive(Serialize, Deserialize)]
// pub struct IncomingMessage {
//     pub round: u8,
//     pub sender: u16,
//     pub message: String, // Serialized message data
// }

// // JavaScript constructors and helpers for message types
// #[wasm_bindgen]
// pub fn create_round1_message(sender: u16, commitment: String) -> JsValue {
//     let msg = Round1Message { sender, commitment };

//     serde_wasm_bindgen::to_value(&msg).unwrap_or(JsValue::NULL)
// }

// #[wasm_bindgen]
// pub fn create_round2_message(
//     sender: u16,
//     rid: String,
//     x: String,
//     sch_commit: String,
//     decommit: String,
// ) -> JsValue {
//     let msg = Round2Message {
//         sender,
//         rid,
//         X: x,
//         sch_commit,
//         decommit,
//     };

//     serde_wasm_bindgen::to_value(&msg).unwrap_or(JsValue::NULL)
// }

// #[wasm_bindgen]
// pub fn create_round3_message(sender: u16, sch_proof: String) -> JsValue {
//     let msg = Round3Message { sender, sch_proof };

//     serde_wasm_bindgen::to_value(&msg).unwrap_or(JsValue::NULL)
// }

// #[wasm_bindgen]
// pub fn create_outgoing_message(
//     round: u8,
//     sender: u16,
//     broadcast: bool,
//     message: String,
// ) -> JsValue {
//     let msg = OutgoingMessage {
//         round,
//         sender,
//         broadcast,
//         message,
//     };

//     serde_wasm_bindgen::to_value(&msg).unwrap_or(JsValue::NULL)
// }

// #[wasm_bindgen]
// pub fn create_incoming_message(round: u8, sender: u16, message: String) -> JsValue {
//     let msg = IncomingMessage {
//         round,
//         sender,
//         message,
//     };

//     serde_wasm_bindgen::to_value(&msg).unwrap_or(JsValue::NULL)
// }

// #[derive(Serialize, Deserialize)]
// pub struct Round1Input {
//     pub i: u16,
//     pub n: u16,
//     pub t: u16,
//     pub sid: String,
// }

// #[wasm_bindgen]
// pub fn create_message_round_1(value: JsValue) -> Result<JsValue, JsValue> {
//     let input: Round1Input = serde_wasm_bindgen::from_value(value)
//         .map_err(|e| JsValue::from_str(&format!("Failed to parse Round1Input: {}", e)))?;

//     let i: u16 = input.i;
//     let n: u16 = input.n;
//     let t: u16 = input.t;
//     let sid = cggmp21_keygen::execution_id::ExecutionId::new(input.sid.as_bytes());

//     let mut rng = rand_dev::DevRng::new();
//     let msg = threshold_keygen::create_message_round_1::<Secp256k1, DevRng, SecurityLevel128, Sha256>(
//         &mut rng, i, t, n, sid,
//     );

//     serde_wasm_bindgen::to_value(&msg)
//         .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round1Message: {}", e)))
// }

// use round_based::rounds_router::simple_store::RoundMsgs;
// #[derive(Serialize, Deserialize)]
// pub struct RoundReliabilityCheckInput {
//     pub sid: String,
//     pub commitments: RoundMsgs<threshold_keygen::MsgRound1<Sha256>>,
//     pub my_commitment: threshold_keygen::MsgRound1<Sha256>,
// }

// #[wasm_bindgen]
// pub fn create_message_round_reliability_check(value: JsValue) -> Result<JsValue, JsValue> {
//     let input: RoundReliabilityCheckInput = serde_wasm_bindgen::from_value(value)
//         .map_err(|e| JsValue::from_str(&format!("Failed to parse Round1Input: {}", e)))?;

//     let sid = cggmp21_keygen::execution_id::ExecutionId::new(input.sid.as_bytes());
//     let commitments = input.commitments;
//     let my_commitment = input.my_commitment;
//     let msg =
//         threshold_keygen::create_message_round_reliability_check(sid, commitments, my_commitment);

//     serde_wasm_bindgen::to_value(&msg)
//         .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round1Message: {}", e)))
// }

// use generic_ec::Scalar;

// #[derive(Serialize, Deserialize)]
// pub struct Round2UniInput {
//     pub i: u16,
//     pub n: u16,
//     pub sigmas: Vec<Scalar<Secp256k1>>,
// }

// #[wasm_bindgen]
// pub fn create_message_round_2_uni(value: JsValue) -> Result<JsValue, JsValue> {
//     let input: Round2UniInput = serde_wasm_bindgen::from_value(value)
//         .map_err(|e| JsValue::from_str(&format!("Failed to parse Round2UniInput: {}", e)))?;
//     let i: u16 = input.i;
//     let n: u16 = input.n;
//     let sigmas: Vec<Scalar<Secp256k1>> = input.sigmas;
    
//     // Get the iterator from the threshold_keygen function
//     let messages_iter = threshold_keygen::create_message_round_2_uni::<Secp256k1, SecurityLevel128, Sha256>(i, n, sigmas);
    
//     // Collect the iterator into a Vec to make it serializable
//     let messages: Vec<_> = messages_iter.collect();

//     serde_wasm_bindgen::to_value(&messages)
//         .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round2UniMessage: {}", e)))
// }

// use generic_ec_zkp::schnorr_pok::ProverSecret;
// #[derive(Serialize, Deserialize)]
// pub struct Round3Input {
//     pub commitments: RoundMsgs<threshold_keygen::MsgRound1<Sha256>>,
//     pub decommitments: RoundMsgs<threshold_keygen::MsgRound2Broad<Secp256k1, SecurityLevel128>>,
//     pub sigmas_msg: RoundMsgs<threshold_keygen::MsgRound2Uni<Secp256k1>>,
//     pub sid: String,
//     pub my_decommitment: threshold_keygen::MsgRound2Broad<Secp256k1, SecurityLevel128>,
//     pub r: ProverSecret<Secp256k1>,
//     pub i: u16,
//     pub n: u16,
//     pub t: u16,
//     pub sigmas: Vec<Scalar<Secp256k1>>,
// }

// #[wasm_bindgen]
// pub fn create_message_round_3(value: JsValue) -> Result<JsValue, JsValue> {
//     let input: Round3Input = serde_wasm_bindgen::from_value(value)
//         .map_err(|e| JsValue::from_str(&format!("Failed to parse Round3Input: {}", e)))?;
//     let sid = cggmp21_keygen::execution_id::ExecutionId::new(input.sid.as_bytes());
//     let commitments = input.commitments;
//     let decommitments = input.decommitments;
//     let sigmas_msg = input.sigmas_msg;
//     let my_decommitment = input.my_decommitment;
//     let i = input.i;
//     let n = input.n;
//     let t = input.t;
//     let sigmas = input.sigmas;
//     let r = input.r;
//     let msg = threshold_keygen::create_message_round_3(
//         commitments,
//         decommitments,
//         sigmas_msg,
//         sid,
//         my_decommitment,
//         i,
//         n,
//         t,
//         r,
//         sigmas,
//     );

//     match msg {
//         Ok(msgg) => serde_wasm_bindgen::to_value(&msgg)
//             .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round3Message: {}", e))),
//         Err(e) => Err(JsValue::from_str(&format!(
//             "Failed to serialize Round3Message: {}",
//             e
//         ))),
//     }
// }

// use generic_ec::{NonZero, Point, SecretScalar};

// #[derive(Serialize, Deserialize)]
// pub struct KeyShareInput {
//     pub sch_proofs: RoundMsgs<threshold_keygen::MsgRound3<Secp256k1>>,
//     pub decommitments: RoundMsgs<threshold_keygen::MsgRound2Broad<Secp256k1, SecurityLevel128>>,
//     pub ys: Vec<NonZero<Point<Secp256k1>>>,
//     pub sid: String,
//     pub my_decommitment: threshold_keygen::MsgRound2Broad<Secp256k1, SecurityLevel128>,
//     pub i: u16,
//     pub n: u16,
//     pub t: u16,
//     pub sigma: NonZero<SecretScalar<Secp256k1>>,
// }

// #[wasm_bindgen]
// pub fn create_key_share(value: JsValue) -> Result<JsValue, JsValue> {
//     let input: KeyShareInput = serde_wasm_bindgen::from_value(value)
//         .map_err(|e| JsValue::from_str(&format!("Failed to parse KeyShareInput: {}", e)))?;
//     let sid = cggmp21_keygen::execution_id::ExecutionId::new(input.sid.as_bytes());
//     let sch_proofs = input.sch_proofs;
//     let decommitments = input.decommitments;
//     let ys = input.ys;
//     let rid = <SecurityLevel128 as cggmp21_keygen::security_level::SecurityLevel>::Rid::default();
//     let my_decommitment = input.my_decommitment;
//     let i = input.i;
//     let n = input.n;
//     let t = input.t;
//     let sigma = input.sigma;
//     let msg = threshold_keygen::create_key_share::<Secp256k1, SecurityLevel128, Sha256>(
//         sch_proofs,
//         decommitments,
//         ys,
//         sid,
//         rid,
//         my_decommitment,
//         i,
//         n,
//         t,
//         sigma,
//     );
//     match msg {
//         Ok(msgg) => serde_wasm_bindgen::to_value(&msgg)
//             .map_err(|e| JsValue::from_str(&format!("Failed to serialize KeyShareMessage: {}", e))),
//         Err(e) => Err(JsValue::from_str(&format!(
//             "Failed to serialize KeyShareMessage: {}",
//             e
//         ))),
//     }
// }

// #[wasm_bindgen]
// pub fn parse_round1_message(value: JsValue) -> Result<JsValue, JsValue> {
//     let msg: Round1Message = serde_wasm_bindgen::from_value(value)
//         .map_err(|e| JsValue::from_str(&format!("Failed to parse Round1Message: {}", e)))?;

//     serde_wasm_bindgen::to_value(&msg)
//         .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round1Message: {}", e)))
// }

// #[wasm_bindgen]
// pub fn parse_round2_message(value: JsValue) -> Result<JsValue, JsValue> {
//     let msg: Round2Message = serde_wasm_bindgen::from_value(value)
//         .map_err(|e| JsValue::from_str(&format!("Failed to parse Round2Message: {}", e)))?;

//     serde_wasm_bindgen::to_value(&msg)
//         .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round2Message: {}", e)))
// }

// #[wasm_bindgen]
// pub fn parse_round3_message(value: JsValue) -> Result<JsValue, JsValue> {
//     let msg: Round3Message = serde_wasm_bindgen::from_value(value)
//         .map_err(|e| JsValue::from_str(&format!("Failed to parse Round3Message: {}", e)))?;

//     serde_wasm_bindgen::to_value(&msg)
//         .map_err(|e| JsValue::from_str(&format!("Failed to serialize Round3Message: {}", e)))
// }

// #[wasm_bindgen]
// pub fn parse_outgoing_message(value: JsValue) -> Result<JsValue, JsValue> {
//     let msg: OutgoingMessage = serde_wasm_bindgen::from_value(value)
//         .map_err(|e| JsValue::from_str(&format!("Failed to parse OutgoingMessage: {}", e)))?;

//     serde_wasm_bindgen::to_value(&msg)
//         .map_err(|e| JsValue::from_str(&format!("Failed to serialize OutgoingMessage: {}", e)))
// }

// #[wasm_bindgen]
// pub fn parse_incoming_message(value: JsValue) -> Result<JsValue, JsValue> {
//     let msg: IncomingMessage = serde_wasm_bindgen::from_value(value)
//         .map_err(|e| JsValue::from_str(&format!("Failed to parse IncomingMessage: {}", e)))?;

//     serde_wasm_bindgen::to_value(&msg)
//         .map_err(|e| JsValue::from_str(&format!("Failed to serialize IncomingMessage: {}", e)))
// }
