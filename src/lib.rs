use std::{fmt, str};
use wasm_bindgen::prelude::*;
use sha2::Sha256;
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme, 
          pkcs8::EncodePublicKey, pkcs8::DecodePublicKey, pkcs8::LineEnding};
use std::collections::HashMap;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde::{Deserialize, Deserializer};
use serde::de::{self, Visitor, MapAccess};

#[wasm_bindgen]
#[derive(Debug, PartialEq)]
/// Represents a privacy-preserving ballot
pub struct Ballot {
    k       : u32,            // k-anonymity parameter
    privkey : RsaPrivateKey,  // private key in PKCS8 PEM encoding
    pubkey  : RsaPublicKey,   // public key in PKCS8 PEM encoding
    votes   : Vec<String>     // list of submitted votes 
}

#[cfg(target_family="wasm")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: String);
}

#[cfg(not(target_family = "wasm"))]
fn log(s: String) {
    println!("{}", s);
}

fn gen_keypair() -> (RsaPublicKey, RsaPrivateKey) {
    let bits = 2048;
    let mut rng : rand::rngs::ThreadRng = rand::thread_rng();
    let privkey = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate an RSA key pair");
    let pubkey = RsaPublicKey::from(&privkey);
    return (pubkey, privkey)
}

/// Encrypts a message using RSA encryption with OAEP padding
/// pubkey - RSA public key
/// msg - message to encrypt as a string
/// Returns a PEM encoding of the encrypted message
fn encrypt_message_internal(pubkey: RsaPublicKey, msg : String) -> String {
    let mut rng = rand::thread_rng();
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let encrypted_msg = pubkey.encrypt(&mut rng, padding, msg.as_bytes()).expect("Failed to encrypt");
    return base64::encode(encrypted_msg)
}

/// Encrypts a message given a PEM encoded public key
/// pubkey - PEM encded public key
/// msg - message to encrypt as a string
/// Returns a PEM encoding of the encrypted message
#[wasm_bindgen]
pub fn encrypt_message(pubkey_pem: &str, msg: String) -> String {
    let pubkey = RsaPublicKey::from_public_key_pem(pubkey_pem).expect("Failed to decode public key PEM");
    return encrypt_message_internal(pubkey, msg)
}

fn decrypt_message(privkey : &RsaPrivateKey, msg: String) -> String {
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let decoded_msg = base64::decode(msg).expect("Failed to decode Base64");
    let decrypted_msg_bytes = privkey.decrypt(padding, &decoded_msg).expect("Failed to decrypt");
    let decrypted_msg = String::from_utf8(decrypted_msg_bytes).expect("Failed to conver to string");
    return decrypted_msg.to_owned();
}

#[wasm_bindgen]
impl Ballot {

    /// Initializes a new ballot.
    /// k - the k-anonymity parameter
    pub fn new(k: u32) -> Ballot {
        let (_pubkey, _privkey) = gen_keypair();

        log(format!("Ballot initialized with k={}", k));

        Ballot {
            k: k,
            privkey: _privkey,
            pubkey: _pubkey,
            votes: Vec::new()
        }
    }

    /// Returns the public key for a given ballot encoded in PEM (PKCS8) format.
    /// ballot - pointer to the Ballot object to extract the public key for
    pub fn get_pubkey_pem(&self) -> String {
        return self.pubkey.to_public_key_pem(LineEnding::default()).unwrap();
    }

    /// Submit an encrypted vote.
    /// encrypted_vote - encrypted vote encoded in Base64
    pub fn vote(&mut self, encrypted_vote : String) {
        let vote = decrypt_message(&self.privkey, encrypted_vote);
        log(format!("Received a new vote: {}", vote));
        
        self.votes.push(vote);
        log(format!("Added vote to list"));
    }

    /// Finalizes the ballot in order to reveal the results.
    pub fn finalize(&self) -> String {
        let total_votes = self.votes.len();
        log(format!("Received a total of {} votes.", total_votes));
        
        if total_votes < self.k as usize {
            log(format!("Received less votes than minimum quorum size. Cannot finalize ballot."));
            return "".to_owned()
        }

        let mut vote_count : HashMap<String, usize> = HashMap::new();
        for vote in &self.votes {
            vote_count.entry(vote.to_owned()).and_modify(|count| *count += 1).or_insert(1);
        }

        // create a sorted votes vector by count
        let mut count_vec : Vec<_> = vote_count.iter().collect();
        count_vec.sort_by(|a, b| b.1.cmp(a.1));
        return count_vec[0].0.to_owned()
    }

}

impl Serialize for Ballot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("Ballot", 4)?;
        state.serialize_field("k", &self.k)?;
        state.serialize_field("privkey", &self.privkey.to_pkcs8_pem(LineEnding::default()).unwrap().as_str())?;
        state.serialize_field("pubkey", &self.get_pubkey_pem())?;
        state.serialize_field("votes", &self.votes)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Ballot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        enum Field { K, PrivKey, PubKey, Votes }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
                where
                    D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("field identifier")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                        where
                            E: de::Error,
                    {
                        match value {
                            "k" => Ok(Field::K),
                            "privkey" => Ok(Field::PrivKey),
                            "pubkey" => Ok(Field::PubKey),
                            "votes" => Ok(Field::Votes),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct BallotVisitor;

        impl<'de> Visitor<'de> for BallotVisitor {
            type Value = Ballot;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Ballot")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Ballot, V::Error>
                where
                    V: MapAccess<'de>,
            {
                let mut k = None;
                let mut privkey = None;
                let mut pubkey = None;
                let mut votes = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::K => {
                            if k.is_some() {
                                return Err(de::Error::duplicate_field("k"));
                            }
                            k = Some(map.next_value()?);
                        }
                        Field::PrivKey => {
                            if privkey.is_some() {
                                return Err(de::Error::duplicate_field("privkey"));
                            }
                            let pem_string: String = map.next_value()?;
                            let priv_key = RsaPrivateKey::from_pkcs8_pem(&pem_string).map_err(|_| de::Error::custom("Invalid RSA Private Key"))?;
                            privkey = Some(priv_key);
                        }
                        Field::PubKey => {
                            if pubkey.is_some() {
                                return Err(de::Error::duplicate_field("pubkey"));
                            }
                            let pem_string: String = map.next_value()?;
                            let pub_key = RsaPublicKey::from_public_key_pem(&pem_string).map_err(|_| de::Error::custom("Invalid RSA Public Key"))?;
                            pubkey = Some(pub_key);
                        }
                        Field::Votes => {
                            if votes.is_some() {
                                return Err(de::Error::duplicate_field("votes"));
                            }
                            votes = Some(map.next_value()?);
                        }
                    }
                }

                let k = k.ok_or_else(|| de::Error::missing_field("k"))?;
                let privkey = privkey.ok_or_else(|| de::Error::missing_field("privkey"))?;
                let pubkey = pubkey.ok_or_else(|| de::Error::missing_field("pubkey"))?;
                let votes = votes.ok_or_else(|| de::Error::missing_field("votes"))?;

                Ok(Ballot { k, privkey, pubkey, votes })
            }
        }

        const FIELDS: &'static [&'static str] = &["k", "privkey", "pubkey", "votes"];
        deserializer.deserialize_struct("Ballot", FIELDS, BallotVisitor)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_keypair() {
        let (_pubkey, _privkey) = gen_keypair();
    }

    #[test]
    fn test_init_ballot() {
        let _ballot = Ballot::new(1);
    }

    #[test]
    fn test_get_pubkey_pem() {
        let ballot = Ballot::new(1);
        let pubkey_pem = ballot.get_pubkey_pem();
        log(format!("Public key: {}", pubkey_pem))
    }

    #[test]
    fn test_vote() {
        let mut ballot = Ballot::new(1);
        let encrypted_vote = encrypt_message(&ballot.get_pubkey_pem(), "test".to_owned());
        ballot.vote(encrypted_vote);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let ballot = Ballot::new(1);
        let msg = "test";
        let encrypted_msg = encrypt_message(&ballot.get_pubkey_pem(), msg.to_owned());
        let decrypted_msg = decrypt_message(&ballot.privkey, encrypted_msg);
        assert!(decrypted_msg == msg)
    }

    #[test]
    fn test_finalize_ballot() {
        let mut ballot = Ballot::new(1);
        let encrypted_vote = encrypt_message(&ballot.get_pubkey_pem(), "test".to_owned());
        ballot.vote(encrypted_vote);
        let winner = ballot.finalize();
        assert!(winner == "test");
        log(format!("Ballot winner: {}", winner))
    }

    #[test]
    fn test_finalize_less_than_k() {
        let _ballot = Ballot::new(1);
        assert!( _ballot.finalize() == "" );
    }

    #[test]
    fn test_serialize_and_deserialize() {
        let mut ballot = Ballot::new(2);
        let encrypted_vote = encrypt_message(&ballot.get_pubkey_pem(), "vote1".to_owned());
        ballot.vote(encrypted_vote);

        let serialized = serde_json::to_string(&ballot).unwrap();

        let deserialized: Ballot = serde_json::from_str(&serialized).unwrap();

        assert_eq!(ballot, deserialized);
    }
}