// aegis-sealer-service/src/core/crypto.rs

use crate::core::{error::AegisError, format::AegisAncient};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};

/// Hashes, signs, and packages the data into an AegisAncient struct.
pub fn seal(
    metadata: String,
    image_data: Vec<u8>,
    private_key: &SigningKey,
) -> Result<AegisAncient, AegisError> {
    let public_key = private_key.verifying_key();
    let mut hasher = Sha256::new();
    hasher.update(metadata.as_bytes());
    hasher.update(&image_data);
    let data_hash = hasher.finalize();
    let signature: Signature = private_key.sign(&data_hash);
    Ok(AegisAncient {
        public_key: public_key.to_sec1_bytes().into_vec(),
        metadata,
        signature: signature.to_bytes().to_vec(),
        image_data,
    })
}