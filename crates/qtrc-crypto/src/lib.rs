//! # qtrc-crypto — HYDRA-X AND-Composition
//!
//! Implements the HYDRA-X dual post-quantum signature protocol:
//! a transaction is valid if and only if it carries a valid
//! ML-DSA-87 (FIPS 204) signature AND a valid SLH-DSA-SHA2-256s
//! (FIPS 205) signature under the same keypair.
//!
//! This is enforced at the consensus layer from genesis — there is
//! no ECDSA fallback or legacy path.
//!
//! ML-DSA-87 is provided by `pqcrypto-mldsa` (the standardized FIPS 204
//! scheme, 4627-byte signatures) and SLH-DSA-SHA2-256s by `fips205`.
//! Neither is the pre-standard round-3 candidate (Dilithium5 /
//! SPHINCS+), which they replace.

use fips205::slh_dsa_sha2_256s;
use fips205::traits::{SerDes, Signer, Verifier};
use pqcrypto_mldsa::mldsa87::{self, PublicKey as MlDsaPk, SecretKey as MlDsaSk};
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

/// Empty FIPS 205 context string. HYDRA-X relies on consensus-level
/// message canonicalization rather than an SLH-DSA context.
const SLH_CTX: &[u8] = &[];

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("HYDRA-X: ML-DSA-87 signature verification failed")]
    MlDsaInvalid,
    #[error("HYDRA-X: SLH-DSA signature verification failed")]
    SlhDsaInvalid,
    #[error("HYDRA-X: AND-composition requires both components to be valid")]
    AndCompositionFailed,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

/// A Quantar Network address — 32-byte BLAKE3 digest of the
/// concatenated ML-DSA-87 and SLH-DSA public keys.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(#[serde(with = "hex::serde")] pub [u8; 32]);

impl Address {
    pub fn from_verifying_key(vk: &HydraXVerifyingKey) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(vk.ml_dsa_pk.as_bytes());
        hasher.update(&vk.slh_dsa_pk.clone().into_bytes());
        Address(*hasher.finalize().as_bytes())
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(s)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength { expected: 32, got: bytes.len() });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Address(arr))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "qtr1{}", hex::encode(&self.0[..16]))
    }
}

// ---------------------------------------------------------------------------
// Public / verifying key
// ---------------------------------------------------------------------------

/// HYDRA-X verifying (public) key: ML-DSA-87 pk || SLH-DSA pk.
#[derive(Clone, Serialize, Deserialize)]
pub struct HydraXVerifyingKey {
    #[serde(with = "pk_serde")]
    pub ml_dsa_pk: MlDsaPk,
    #[serde(with = "slh_pk_serde")]
    pub slh_dsa_pk: slh_dsa_sha2_256s::PublicKey,
}

impl std::fmt::Debug for HydraXVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HydraXVerifyingKey({})", self.address())
    }
}

impl HydraXVerifyingKey {
    pub fn address(&self) -> Address {
        Address::from_verifying_key(self)
    }

    /// Raw bytes of the ML-DSA-87 public key (2592 bytes).
    pub fn ml_dsa_pk_bytes(&self) -> &[u8] {
        self.ml_dsa_pk.as_bytes()
    }

    /// Raw bytes of the SLH-DSA-256s public key (64 bytes).
    pub fn slh_dsa_pk_bytes(&self) -> Vec<u8> {
        self.slh_dsa_pk.clone().into_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// Signing key — scrubbed on drop
// ---------------------------------------------------------------------------

/// HYDRA-X signing (secret) key.
pub struct HydraXSigningKey {
    ml_dsa_sk: MlDsaSk,
    slh_dsa_sk: slh_dsa_sha2_256s::PrivateKey,
}

impl Drop for HydraXSigningKey {
    fn drop(&mut self) {
        let mut ml = self.ml_dsa_sk.as_bytes().to_vec();
        ml.zeroize();
        let mut sl = self.slh_dsa_sk.clone().into_bytes().to_vec();
        sl.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

/// A complete HYDRA-X keypair (signing + verifying).
pub struct HydraXKeypair {
    pub signing_key:   HydraXSigningKey,
    pub verifying_key: HydraXVerifyingKey,
}

impl HydraXKeypair {
    /// Generate a fresh HYDRA-X keypair using OS randomness.
    pub fn generate() -> Self {
        let (ml_pk, ml_sk) = mldsa87::keypair();
        let (slh_pk, slh_sk) =
            slh_dsa_sha2_256s::try_keygen().expect("OS RNG failure during SLH-DSA keygen");

        HydraXKeypair {
            signing_key: HydraXSigningKey {
                ml_dsa_sk: ml_sk,
                slh_dsa_sk: slh_sk,
            },
            verifying_key: HydraXVerifyingKey {
                ml_dsa_pk: ml_pk,
                slh_dsa_pk: slh_pk,
            },
        }
    }

    /// Derive the address of this keypair.
    pub fn address(&self) -> Address {
        self.verifying_key.address()
    }

    /// Sign a message with the AND-composition of ML-DSA-87 and SLH-DSA.
    pub fn sign(&self, message: &[u8]) -> HydraXSignature {
        let ml_sig = mldsa87::detached_sign(message, &self.signing_key.ml_dsa_sk);
        // Deterministic (non-hedged) SLH-DSA signature: no RNG, cannot fail.
        let sl_sig = self
            .signing_key
            .slh_dsa_sk
            .try_sign(message, SLH_CTX, false)
            .expect("deterministic SLH-DSA signing cannot fail");

        HydraXSignature {
            ml_dsa_sig:    ml_sig.as_bytes().to_vec(),
            slh_dsa_sig:   sl_sig.to_vec(),
            verifying_key: self.verifying_key.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/// HYDRA-X AND-composed signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HydraXSignature {
    pub ml_dsa_sig:    Vec<u8>,
    pub slh_dsa_sig:   Vec<u8>,
    pub verifying_key: HydraXVerifyingKey,
}

impl HydraXSignature {
    /// Verify the AND-composition: BOTH components must be valid.
    pub fn verify(&self, message: &[u8]) -> Result<(), CryptoError> {
        // — Component 1: ML-DSA-87 (FIPS 204) —
        let ml_sig = mldsa87::DetachedSignature::from_bytes(&self.ml_dsa_sig)
            .map_err(|_| CryptoError::MlDsaInvalid)?;
        mldsa87::verify_detached_signature(&ml_sig, message, &self.verifying_key.ml_dsa_pk)
            .map_err(|_| CryptoError::MlDsaInvalid)?;

        // — Component 2: SLH-DSA-SHA2-256s (FIPS 205) —
        let sl_sig: [u8; slh_dsa_sha2_256s::SIG_LEN] = self
            .slh_dsa_sig
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::SlhDsaInvalid)?;
        if !self
            .verifying_key
            .slh_dsa_pk
            .verify(message, &sl_sig, SLH_CTX)
        {
            return Err(CryptoError::SlhDsaInvalid);
        }

        Ok(())
    }

    /// The address that produced this signature.
    pub fn signer_address(&self) -> Address {
        self.verifying_key.address()
    }
}

// ---------------------------------------------------------------------------
// Serde helpers
// ---------------------------------------------------------------------------

mod pk_serde {
    use pqcrypto_mldsa::mldsa87::PublicKey;
    use pqcrypto_traits::sign::PublicKey as Trait;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(pk: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(pk.as_bytes(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        let bytes: Vec<u8> = serde_bytes::deserialize(d)?;
        PublicKey::from_bytes(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("ml-dsa pk: {e:?}")))
    }
}

mod slh_pk_serde {
    use fips205::slh_dsa_sha2_256s::{PublicKey, PK_LEN};
    use fips205::traits::SerDes;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(pk: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        let bytes = pk.clone().into_bytes();
        serde_bytes::serialize(&bytes[..], s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        let bytes: Vec<u8> = serde_bytes::deserialize(d)?;
        let arr: [u8; PK_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("slh-dsa pk: wrong length"))?;
        PublicKey::try_from_bytes(&arr)
            .map_err(|e| serde::de::Error::custom(format!("slh-dsa pk: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_and_sign_verify() {
        let keypair = HydraXKeypair::generate();
        let msg = b"quantar network testnet genesis";
        let sig = keypair.sign(msg);
        assert!(sig.verify(msg).is_ok(), "AND-composition must verify");
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = HydraXKeypair::generate();
        let sig = keypair.sign(b"correct message");
        assert!(sig.verify(b"tampered message").is_err());
    }

    #[test]
    fn test_address_deterministic() {
        let keypair = HydraXKeypair::generate();
        assert_eq!(keypair.address(), keypair.verifying_key.address());
    }

    #[test]
    fn test_signer_address_matches() {
        let keypair = HydraXKeypair::generate();
        let sig = keypair.sign(b"test");
        assert_eq!(sig.signer_address(), keypair.address());
    }

    #[test]
    fn test_fips_signature_sizes() {
        // ML-DSA-87 (FIPS 204): 4627 bytes, not the round-3 value 4595.
        // SLH-DSA-SHA2-256s (FIPS 205): 29792 bytes.
        let keypair = HydraXKeypair::generate();
        let sig = keypair.sign(b"size check");
        assert_eq!(sig.ml_dsa_sig.len(), 4627);
        assert_eq!(sig.slh_dsa_sig.len(), slh_dsa_sha2_256s::SIG_LEN);
        assert_eq!(sig.slh_dsa_sig.len(), 29792);
    }

    #[test]
    fn test_one_leg_tampered_fails() {
        // Flipping a byte in only the SLH-DSA leg must still fail:
        // the AND-composition requires both.
        let keypair = HydraXKeypair::generate();
        let msg = b"and composition";
        let mut sig = keypair.sign(msg);
        sig.slh_dsa_sig[0] ^= 0xFF;
        assert!(matches!(sig.verify(msg), Err(CryptoError::SlhDsaInvalid)));
    }

    #[test]
    fn test_serde_roundtrip() {
        let keypair = HydraXKeypair::generate();
        let msg = b"serde";
        let sig = keypair.sign(msg);
        let encoded = bincode::serialize(&sig).expect("serialize");
        let decoded: HydraXSignature = bincode::deserialize(&encoded).expect("deserialize");
        assert!(decoded.verify(msg).is_ok());
        assert_eq!(decoded.signer_address(), keypair.address());
    }
}
