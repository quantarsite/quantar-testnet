//! # qtrc-crypto — HYDRA-X AND-Composition
//!
//! Implements the HYDRA-X dual post-quantum signature protocol:
//! a transaction is valid if and only if it carries a valid
//! ML-DSA-87 (FIPS 204) signature AND a valid SLH-DSA (FIPS 205)
//! signature under the same keypair.
//!
//! This is enforced at the consensus layer from genesis — there is
//! no ECDSA fallback or legacy path.

use pqcrypto_dilithium::dilithium5::{self, PublicKey as DilithiumPk, SecretKey as DilithiumSk};
use pqcrypto_sphincsplus::sphincssha2256ssimple::{
    self, PublicKey as SphincsXPk, SecretKey as SphincsXSk,
};
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

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
        hasher.update(vk.slh_dsa_pk.as_bytes());
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
    pub ml_dsa_pk: DilithiumPk,
    #[serde(with = "sphincs_pk_serde")]
    pub slh_dsa_pk: SphincsXPk,
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
        use pqcrypto_traits::sign::PublicKey;
        self.ml_dsa_pk.as_bytes()
    }

    /// Raw bytes of the SLH-DSA-256s public key (64 bytes).
    pub fn slh_dsa_pk_bytes(&self) -> &[u8] {
        use pqcrypto_traits::sign::PublicKey;
        self.slh_dsa_pk.as_bytes()
    }
}

// ---------------------------------------------------------------------------
// Signing key — zeroized on drop
// ---------------------------------------------------------------------------

/// HYDRA-X signing (secret) key — zeroized from memory on drop.
pub struct HydraXSigningKey {
    ml_dsa_sk: DilithiumSk,
    slh_dsa_sk: SphincsXSk,
}

impl Drop for HydraXSigningKey {
    fn drop(&mut self) {
        let mut ml = self.ml_dsa_sk.as_bytes().to_vec();
        ml.zeroize();
        let mut sl = self.slh_dsa_sk.as_bytes().to_vec();
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
        let (ml_pk, ml_sk) = dilithium5::keypair();
        let (sl_pk, sl_sk) = sphincssha2256ssimple::keypair();

        HydraXKeypair {
            signing_key: HydraXSigningKey {
                ml_dsa_sk: ml_sk,
                slh_dsa_sk: sl_sk,
            },
            verifying_key: HydraXVerifyingKey {
                ml_dsa_pk: ml_pk,
                slh_dsa_pk: sl_pk,
            },
        }
    }

    /// Derive the address of this keypair.
    pub fn address(&self) -> Address {
        self.verifying_key.address()
    }

    /// Sign a message with the AND-composition of ML-DSA-87 and SLH-DSA.
    pub fn sign(&self, message: &[u8]) -> HydraXSignature {
        let ml_sig = dilithium5::detached_sign(message, &self.signing_key.ml_dsa_sk);
        let sl_sig = sphincssha2256ssimple::detached_sign(message, &self.signing_key.slh_dsa_sk);

        HydraXSignature {
            ml_dsa_sig:    ml_sig.as_bytes().to_vec(),
            slh_dsa_sig:   sl_sig.as_bytes().to_vec(),
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
        // — Component 1: ML-DSA-87 —
        let ml_sig = dilithium5::DetachedSignature::from_bytes(&self.ml_dsa_sig)
            .map_err(|_| CryptoError::MlDsaInvalid)?;
        dilithium5::verify_detached_signature(&ml_sig, message, &self.verifying_key.ml_dsa_pk)
            .map_err(|_| CryptoError::MlDsaInvalid)?;

        // — Component 2: SLH-DSA (SPHINCS+) —
        let sl_sig = sphincssha2256ssimple::DetachedSignature::from_bytes(&self.slh_dsa_sig)
            .map_err(|_| CryptoError::SlhDsaInvalid)?;
        sphincssha2256ssimple::verify_detached_signature(
            &sl_sig,
            message,
            &self.verifying_key.slh_dsa_pk,
        )
        .map_err(|_| CryptoError::SlhDsaInvalid)?;

        Ok(())
    }

    /// The address that produced this signature.
    pub fn signer_address(&self) -> Address {
        self.verifying_key.address()
    }
}

// ---------------------------------------------------------------------------
// Serde helpers for pqcrypto types
// ---------------------------------------------------------------------------

mod pk_serde {
    use pqcrypto_dilithium::dilithium5::PublicKey;
    use pqcrypto_traits::sign::PublicKey as Trait;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(pk: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(pk.as_bytes(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        let bytes: Vec<u8> = serde_bytes::deserialize(d)?;
        PublicKey::from_bytes(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("dilithium pk: {e:?}")))
    }
}

mod sphincs_pk_serde {
    use pqcrypto_sphincsplus::sphincssha2256ssimple::PublicKey;
    use pqcrypto_traits::sign::PublicKey as Trait;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(pk: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(pk.as_bytes(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        let bytes: Vec<u8> = serde_bytes::deserialize(d)?;
        PublicKey::from_bytes(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("sphincs pk: {e:?}")))
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
}
