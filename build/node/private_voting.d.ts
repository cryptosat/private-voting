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
