/* tslint:disable */
/* eslint-disable */
/**
* Encrypts a message given a PEM encoded public key
* pubkey - PEM encded public key
* msg - message to encrypt as a string
* Returns a PEM encoding of the encrypted message
* @param {string} pubkey_pem
* @param {string} msg
* @returns {string}
*/
export function encrypt_message(pubkey_pem: string, msg: string): string;
/**
* Represents a privacy-preserving ballot
*/
export class Ballot {
  free(): void;
/**
* Initializes a new ballot.
* k - the k-anonymity parameter
* @param {number} k
* @returns {Ballot}
*/
  static new(k: number): Ballot;
/**
* Returns the public key for a given ballot encoded in PEM (PKCS8) format.
* ballot - pointer to the Ballot object to extract the public key for
* @returns {string}
*/
  get_pubkey_pem(): string;
/**
* Submit an encrypted vote.
* encrypted_vote - encrypted vote encoded in Base64
* @param {string} encrypted_vote
*/
  vote(encrypted_vote: string): void;
/**
* Finalizes the ballot in order to reveal the results.
* @returns {string}
*/
  finalize(): string;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_ballot_free: (a: number) => void;
  readonly encrypt_message: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly ballot_new: (a: number) => number;
  readonly ballot_get_pubkey_pem: (a: number, b: number) => void;
  readonly ballot_vote: (a: number, b: number, c: number) => void;
  readonly ballot_finalize: (a: number, b: number) => void;
  readonly __wbindgen_free: (a: number, b: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_malloc: (a: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
