/* tslint:disable */
/* eslint-disable */
export function create_message(sender: string, round: number, data: number): any;
export class Protocol {
  free(): void;
  constructor(party_id: string);
  run_round_1(): any;
  run_round_2(messages_js: any): number;
  get_party_id(): string;
  get_own_number(): number | undefined;
}
/**
 * WASM wrapper for AuxGenProtocol
 */
export class StatefulAuxGenProtocol {
  free(): void;
  constructor(params: any);
  /**
   * Generate commitment for Round 1 of the protocol
   */
  round1_generate_commitment(): any;
  /**
   * Set commitments received from other parties in Round 1
   */
  set_round1_commitments(commitments: any): void;
  /**
   * Create reliability check message if reliable broadcast is enforced
   */
  create_reliability_check(): any;
  /**
   * Get decommitment for Round 2
   */
  round2_get_decommitment(): any;
  /**
   * Set decommitments received from other parties in Round 2
   */
  set_round2_decommitments(decommitments: any): void;
  /**
   * Validate decommitments and compute combined random bytes
   */
  validate_round2_decommitments(): void;
  /**
   * Create messages for Round 3
   */
  round3_create_messages(): any;
  /**
   * Set messages received from other parties in Round 3
   */
  set_round3_messages(messages: any): void;
  /**
   * Validate proofs and generate the final output
   */
  finalize(): any;
}
/**
 * WASM wrapper for HierarchicalThresholdKeygenProtocol
 */
export class StatefulHierarchicalThresholdKeygenProtocol {
  free(): void;
  constructor(params: any);
  /**
   * Generate commitment for Round 1 of the protocol
   */
  round1_generate_commitment(): any;
  /**
   * Set round 1 commitments from other parties
   */
  set_round1_commitments(commitments: any): void;
  /**
   * Create reliability check message (optional)
   */
  create_reliability_check(): any;
  /**
   * Get decommitment for round 2 broadcast
   */
  round2_get_decommitment(): any;
  /**
   * Get unicast messages for round 2
   */
  round2_get_unicast_messages(): any;
  /**
   * Set round 2 decommitments from other parties
   */
  set_round2_decommitments(decommitments: any): void;
  /**
   * Set round 2 sigma shares from other parties
   */
  set_round2_sigmas(sigmas: any): void;
  /**
   * Validate round 2 data and prepare for round 3
   */
  validate_round2_and_prepare_round3(): void;
  /**
   * Generate Schnorr proof for round 3
   */
  round3_generate_proof(): any;
  /**
   * Set round 3 Schnorr proofs from other parties
   */
  set_round3_schnorr_proofs(schnorr_proofs: any): void;
  /**
   * Finalize key generation and get the key share
   */
  finalize_key_generation(): any;
  /**
   * Complete round 2 (convenience method that combines setting data and validation)
   */
  complete_round2(commitments: any, decommitments: any, sigmas: any): void;
  /**
   * Complete round 3 and generate key share (convenience method)
   */
  complete_round3_and_generate_key_share(commitments: any, decommitments: any, sigmas: any, schnorr_proofs: any): any;
  /**
   * Get the current protocol state for debugging (returns serialized state info)
   */
  get_protocol_state_info(): any;
}
/**
 * WASM wrapper for KeygenProtocol
 */
export class StatefulKeygenProtocol {
  free(): void;
  constructor(params: any);
  /**
   * Generate commitment for Round 1 of the protocol
   */
  round1_generate_commitment(): any;
  round2_uni(): any;
  round2_broad(): any;
  set_commitments_from_r1_store(commitments: any): void;
  set_decommitments_from_r2_store(decommitments: any): void;
  set_sigmas_from_r2_store(sigmas: any): void;
  round3(commitments: any, decommitments: any, sigmas: any): any;
  set_commitments_from_r3_store(schnorrs: any): void;
  round_key_share(commitments: any, decommitments: any, sigmas: any, schnorrs: any): any;
}
/**
 * WASM wrapper for SigningProtocol
 */
export class StatefulSigningProtocol {
  free(): void;
  /**
   * Create a new signing protocol instance
   */
  constructor(params: any, key_share: any);
  /**
   * Generate round 1a message (broadcast)
   */
  round1a_generate_message(): any;
  /**
   * Set round 1a messages from other parties
   */
  set_round1a_messages(messages: any): void;
  /**
   * Create reliability check message if reliable broadcast is enforced
   */
  create_reliability_check(): any;
  /**
   * Generate round 1b messages (P2P)
   */
  round1b_generate_messages(): any;
  /**
   * Set round 1b messages from other parties
   */
  set_round1b_messages(messages: any): void;
  /**
   * Validate round 1b proofs
   */
  validate_round1b_proofs(): void;
  /**
   * Generate round 2 messages (P2P)
   */
  round2_generate_messages(): any;
  /**
   * Set round 2 messages from other parties
   */
  set_round2_messages(messages: any): void;
  /**
   * Generate round 3 messages (P2P)
   */
  round3_generate_messages(): any;
  /**
   * Set round 3 messages from other parties
   */
  set_round3_messages(messages: any): void;
  /**
   * Generate presignature from the protocol state
   */
  generate_presignature(): any;
  /**
   * Generate round 4 message (partial signature) - returns undefined if no message to sign
   */
  round4_generate_message(): any;
  /**
   * Set round 4 messages from other parties
   */
  set_round4_messages(messages: any): void;
  /**
   * Generate final signature from round 4 results
   */
  generate_signature(my_partial_sig: any): any;
  /**
   * Verify a signature against a public key and message
   * Takes signature (JsValue), public_key (hex string), and message (hex string)
   */
  static verify_signature(signature: any, public_key_hex: string, message_hex: string): boolean;
  /**
   * Get public key from a key share (helper method for verification)
   */
  static get_public_key_from_keyshare(key_share: any): string;
  /**
   * Generate precompute tables for all parties participating in signing
   * This creates tables dynamically for benchmarking purposes
   */
  generate_precompute_tables(): any;
  /**
   * Generate precompute table for a specific party
   * This is useful for on-demand table generation
   */
  generate_precompute_table_for_party(party_index: number): any;
  /**
   * Set cached precompute tables for the protocol
   * This allows for using pre-generated tables for better performance
   */
  set_cached_precompute_tables(tables: any): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_statefulkeygenprotocol_free: (a: number, b: number) => void;
  readonly statefulkeygenprotocol_new: (a: any) => [number, number, number];
  readonly statefulkeygenprotocol_round1_generate_commitment: (a: number) => [number, number, number];
  readonly statefulkeygenprotocol_round2_uni: (a: number) => [number, number, number];
  readonly statefulkeygenprotocol_round2_broad: (a: number) => [number, number, number];
  readonly statefulkeygenprotocol_set_commitments_from_r1_store: (a: number, b: any) => [number, number];
  readonly statefulkeygenprotocol_set_decommitments_from_r2_store: (a: number, b: any) => [number, number];
  readonly statefulkeygenprotocol_set_sigmas_from_r2_store: (a: number, b: any) => [number, number];
  readonly statefulkeygenprotocol_round3: (a: number, b: any, c: any, d: any) => [number, number, number];
  readonly statefulkeygenprotocol_set_commitments_from_r3_store: (a: number, b: any) => [number, number];
  readonly statefulkeygenprotocol_round_key_share: (a: number, b: any, c: any, d: any, e: any) => [number, number, number];
  readonly __wbg_statefulhierarchicalthresholdkeygenprotocol_free: (a: number, b: number) => void;
  readonly statefulhierarchicalthresholdkeygenprotocol_new: (a: any) => [number, number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_round1_generate_commitment: (a: number) => [number, number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_set_round1_commitments: (a: number, b: any) => [number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_create_reliability_check: (a: number) => [number, number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_round2_get_decommitment: (a: number) => [number, number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_round2_get_unicast_messages: (a: number) => [number, number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_set_round2_decommitments: (a: number, b: any) => [number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_set_round2_sigmas: (a: number, b: any) => [number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_validate_round2_and_prepare_round3: (a: number) => [number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_round3_generate_proof: (a: number) => [number, number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_set_round3_schnorr_proofs: (a: number, b: any) => [number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_finalize_key_generation: (a: number) => [number, number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_complete_round2: (a: number, b: any, c: any, d: any) => [number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_complete_round3_and_generate_key_share: (a: number, b: any, c: any, d: any, e: any) => [number, number, number];
  readonly statefulhierarchicalthresholdkeygenprotocol_get_protocol_state_info: (a: number) => [number, number, number];
  readonly __wbg_statefulauxgenprotocol_free: (a: number, b: number) => void;
  readonly statefulauxgenprotocol_new: (a: any) => any;
  readonly statefulauxgenprotocol_round1_generate_commitment: (a: number) => [number, number, number];
  readonly statefulauxgenprotocol_set_round1_commitments: (a: number, b: any) => [number, number];
  readonly statefulauxgenprotocol_create_reliability_check: (a: number) => [number, number, number];
  readonly statefulauxgenprotocol_round2_get_decommitment: (a: number) => [number, number, number];
  readonly statefulauxgenprotocol_set_round2_decommitments: (a: number, b: any) => [number, number];
  readonly statefulauxgenprotocol_validate_round2_decommitments: (a: number) => [number, number];
  readonly statefulauxgenprotocol_round3_create_messages: (a: number) => [number, number, number];
  readonly statefulauxgenprotocol_set_round3_messages: (a: number, b: any) => [number, number];
  readonly statefulauxgenprotocol_finalize: (a: number) => [number, number, number];
  readonly __wbg_statefulsigningprotocol_free: (a: number, b: number) => void;
  readonly statefulsigningprotocol_new: (a: any, b: any) => [number, number, number];
  readonly statefulsigningprotocol_round1a_generate_message: (a: number) => [number, number, number];
  readonly statefulsigningprotocol_set_round1a_messages: (a: number, b: any) => [number, number];
  readonly statefulsigningprotocol_create_reliability_check: (a: number) => [number, number, number];
  readonly statefulsigningprotocol_round1b_generate_messages: (a: number) => [number, number, number];
  readonly statefulsigningprotocol_set_round1b_messages: (a: number, b: any) => [number, number];
  readonly statefulsigningprotocol_validate_round1b_proofs: (a: number) => [number, number];
  readonly statefulsigningprotocol_round2_generate_messages: (a: number) => [number, number, number];
  readonly statefulsigningprotocol_set_round2_messages: (a: number, b: any) => [number, number];
  readonly statefulsigningprotocol_round3_generate_messages: (a: number) => [number, number, number];
  readonly statefulsigningprotocol_set_round3_messages: (a: number, b: any) => [number, number];
  readonly statefulsigningprotocol_generate_presignature: (a: number) => [number, number, number];
  readonly statefulsigningprotocol_round4_generate_message: (a: number) => any;
  readonly statefulsigningprotocol_set_round4_messages: (a: number, b: any) => [number, number];
  readonly statefulsigningprotocol_generate_signature: (a: number, b: any) => [number, number, number];
  readonly statefulsigningprotocol_verify_signature: (a: any, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly statefulsigningprotocol_get_public_key_from_keyshare: (a: any) => [number, number, number, number];
  readonly statefulsigningprotocol_generate_precompute_tables: (a: number) => [number, number, number];
  readonly statefulsigningprotocol_generate_precompute_table_for_party: (a: number, b: number) => [number, number, number];
  readonly statefulsigningprotocol_set_cached_precompute_tables: (a: number, b: any) => [number, number];
  readonly __wbg_protocol_free: (a: number, b: number) => void;
  readonly protocol_new: (a: number, b: number) => number;
  readonly protocol_run_round_1: (a: number) => any;
  readonly protocol_run_round_2: (a: number, b: any) => number;
  readonly protocol_get_party_id: (a: number) => [number, number];
  readonly protocol_get_own_number: (a: number) => number;
  readonly create_message: (a: number, b: number, c: number, d: number) => any;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_4: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_export_6: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly closure216_externref_shim: (a: number, b: number, c: any) => void;
  readonly closure293_externref_shim: (a: number, b: number, c: any, d: any) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
