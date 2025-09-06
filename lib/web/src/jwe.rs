use std::convert::TryFrom;

use didkit::{error::Error, ssi::jwk::Params, DID_METHODS, JWK};
use sha2::Digest;

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use byteorder::{BigEndian, WriteBytesExt};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand_chacha::{
    rand_core::{OsRng, RngCore, SeedableRng},
    ChaCha20Rng,
};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

#[derive(Serialize, Deserialize)]
struct ProtectedHeader {
    enc: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RecipientHeader {
    alg: String,
    iv: String,
    tag: String,
    epk: EphemeralPublicKey,
    kid: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Recipient {
    encrypted_key: String,
    header: RecipientHeader,
}

#[derive(Serialize, Deserialize, Debug)]
struct MultiRecipientJWE {
    #[serde(rename = "protected")]
    protected_header: String,
    iv: String,
    ciphertext: String,
    tag: String,
    recipients: Vec<Recipient>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct EphemeralPublicKey {
    kty: String,
    crv: String,
    x: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JWE {
    #[serde(rename = "protected")]
    protected_header: String,
    iv: String,
    ciphertext: String,
    tag: String,
    recipients: Vec<RecipientInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct RecipientInfo {
    encrypted_key: String,
    header: RecipientHeader,
}

impl JWE {
    /// Encrypts content to multiple recipients using XChaCha20Poly1305
    ///
    /// # Arguments
    /// * `content` - Byte slice of the content to encrypt
    /// * `recipients` - List of recipient DIDs
    pub async fn encrypt(content: &[u8], recipients: &[String]) -> Result<Self, Error> {
        let mut rng = ChaCha20Rng::from_rng(OsRng).unwrap();

        let mut iv = [0u8; 24];
        rng.fill_bytes(&mut iv);

        let protected = ProtectedHeader {
            enc: "XC20P".to_string(),
        };
        let protected_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&protected)?.as_bytes());

        // Generate content encryption key (CEK)
        let mut cek = [0u8; 32];
        rng.fill_bytes(&mut cek);

        let mut recipient_infos = Vec::new();

        for recipient_did in recipients {
            let resolver = DID_METHODS.to_resolver();
            let (res_meta, doc, _) = resolver.resolve(recipient_did, &Default::default()).await;

            if res_meta.error.is_some() {
                continue;
            }

            let doc = doc.ok_or(Error::UnableToGetVerificationMethod)?;

            // Get key agreement key
            let key_agreements = doc
                .key_agreement
                .as_ref()
                .ok_or(Error::UnableToGetVerificationMethod)?;

            for key_agreement in key_agreements {
                // Try to extract recipient's X25519 public key from various VM encodings
                let receiver_public_bytes_opt: Option<Vec<u8>> = match &key_agreement {
                    didkit::ssi::did::VerificationMethod::Map(vm) => {
                        // 1) publicKeyBase58
                        if let Some(pk_b58) = vm.public_key_base58.clone() {
                            bs58::decode(&pk_b58).into_vec().ok()
                        // 2) publicKeyJwk with crv X25519
                        } else if let Some(jwk) = vm.public_key_jwk.clone() {
                            match &jwk.params {
                                Params::OKP(okp) if okp.curve == "X25519" => {
                                    Some(okp.public_key.0.clone())
                                }
                                _ => None,
                            }
                        // 3) publicKeyMultibase (Multikey)
                        } else if let Some(ps) = &vm.property_set {
                            if let Some(mb) = ps
                                .get("publicKeyMultibase")
                                .and_then(|v| v.as_str())
                            {
                                decode_public_key_multibase(mb)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    // Unsupported VM encoding (e.g., reference) — skip
                    _ => None,
                };

                let receiver_public_bytes = match receiver_public_bytes_opt {
                    Some(bytes) if bytes.len() == 32 => bytes,
                    _ => continue, // Skip keys we can't interpret as X25519
                };

                let receiver_mont = match <[u8; 32]>::try_from(receiver_public_bytes.as_slice()) {
                    Ok(arr) => X25519Public::from(arr),
                    Err(_) => continue,
                };

                let mut recipient_iv = [0u8; 24]; // Updated to 24 bytes
                rng.fill_bytes(&mut recipient_iv);

                let ephemeral_secret = StaticSecret::from([0u8; 32]);
                let ephemeral_public = X25519Public::from(&ephemeral_secret);

                let shared_secret = ephemeral_secret.diffie_hellman(&receiver_mont);

                let kek = concat_kdf(
                    shared_secret.as_bytes(),
                    256,
                    "ECDH-ES+XC20PKW",
                    None, // apu (producer info)
                );

                // Encrypt CEK for this recipient
                let cipher = XChaCha20Poly1305::new_from_slice(&kek).map_err(|_| {
                    Error::JWK(didkit::ssi::jwk::Error::InvalidKeyLength(kek.len()))
                })?;

                let nonce = XNonce::from_slice(&recipient_iv);
                let mut encrypted_key = cipher
                    .encrypt(nonce, &cek[..])
                    .map_err(|_| Error::UnableToGenerateDID)?;

                let tag = encrypted_key.split_off(encrypted_key.len() - 16);

                // Create recipient header
                let header = RecipientHeader {
                    alg: "ECDH-ES+XC20PKW".to_string(),
                    iv: URL_SAFE_NO_PAD.encode(&recipient_iv),
                    tag: URL_SAFE_NO_PAD.encode(&tag), // Store the tag separately
                    epk: EphemeralPublicKey {
                        kty: "OKP".to_string(),
                        crv: "X25519".to_string(),
                        x: URL_SAFE_NO_PAD.encode(ephemeral_public.as_bytes()),
                    },
                    kid: key_agreement.get_id(&recipient_did).to_string(),
                };

                recipient_infos.push(RecipientInfo {
                    encrypted_key: URL_SAFE_NO_PAD.encode(encrypted_key),
                    header,
                });
            }
        }

        let cipher = XChaCha20Poly1305::new_from_slice(&cek)
            .map_err(|_| Error::JWK(didkit::ssi::jwk::Error::InvalidKeyLength(cek.len())))?;

        let nonce = XNonce::from_slice(&iv);

        let payload = Payload {
            msg: content,
            aad: protected_b64.as_bytes(),
        };

        let mut encrypted = cipher
            .encrypt(nonce, payload)
            .map_err(|_| Error::UnableToGenerateDID)?;

        // Split ciphertext and tag
        let tag = encrypted.split_off(encrypted.len() - 16);

        Ok(JWE {
            protected_header: protected_b64,
            iv: URL_SAFE_NO_PAD.encode(iv),
            ciphertext: URL_SAFE_NO_PAD.encode(encrypted),
            tag: URL_SAFE_NO_PAD.encode(tag),
            recipients: recipient_infos,
        })
    }

    pub fn decrypt(&self, jwks: &[JWK]) -> Option<Vec<u8>> {
        for jwk in jwks {
            // Convert JWK to X25519
            let x25519_key = match convert_ed25519_to_x25519(jwk) {
                Ok(keys) => keys,
                Err(_) => continue,
            };

            // Try each recipient
            for recipient in &self.recipients {
                let epk_bytes = match URL_SAFE_NO_PAD.decode(&recipient.header.epk.x) {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };

                let ephemeral_public =
                    X25519Public::from(<[u8; 32]>::try_from(epk_bytes.as_slice()).ok()?);

                let shared_secret = x25519_key.diffie_hellman(&ephemeral_public);

                // Replace HKDF with concatKDF
                let kek = concat_kdf(
                    shared_secret.as_bytes(),
                    256,
                    "ECDH-ES+XC20PKW",
                    None, // apu
                );

                // Decrypt the content encryption key (CEK)
                let cipher = match XChaCha20Poly1305::new_from_slice(&kek) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let recipient_iv = match URL_SAFE_NO_PAD.decode(&recipient.header.iv) {
                    Ok(iv) => iv,
                    Err(_) => continue,
                };

                let nonce = XNonce::from_slice(&recipient_iv);

                let recipient_tag = match URL_SAFE_NO_PAD.decode(&recipient.header.tag) {
                    Ok(recipient_tag) => recipient_tag,
                    Err(_) => continue,
                };

                // Combine encrypted_key and tag
                let mut encrypted_key_with_tag =
                    match URL_SAFE_NO_PAD.decode(&recipient.encrypted_key) {
                        Ok(encrypted_key) => encrypted_key,
                        Err(_) => continue,
                    };

                encrypted_key_with_tag.extend_from_slice(&recipient_tag);

                let cek = match cipher.decrypt(nonce, encrypted_key_with_tag.as_ref()) {
                    Ok(key) => key,
                    Err(_) => continue,
                };

                // Use the CEK to decrypt the content
                let content_cipher = match XChaCha20Poly1305::new_from_slice(&cek) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let iv = match URL_SAFE_NO_PAD.decode(&self.iv) {
                    Ok(iv) => iv,
                    Err(_) => continue,
                };

                let content_nonce = XNonce::from_slice(iv.as_slice());
                let mut ciphertext_with_tag = match URL_SAFE_NO_PAD.decode(&self.ciphertext) {
                    Ok(ciphertext) => ciphertext,
                    Err(_) => continue,
                };

                let tag = match URL_SAFE_NO_PAD.decode(&self.tag) {
                    Ok(tag) => tag,
                    Err(_) => continue,
                };

                ciphertext_with_tag.extend_from_slice(tag.as_slice());
                let payload = Payload {
                    msg: &ciphertext_with_tag.as_ref(),
                    aad: self.protected_header.as_bytes(),
                };

                match content_cipher.decrypt(content_nonce, payload) {
                    Ok(plaintext) => return Some(plaintext),
                    Err(_) => continue,
                }
            }
        }

        None
    }
}

// Helper function to convert Ed25519 JWK to X25519 keys
fn convert_ed25519_to_x25519(jwk: &JWK) -> Result<StaticSecret, Error> {
    match &jwk.params {
        Params::OKP(params) if params.curve == "Ed25519" => {
            let mont_secret = if let Some(private) = &params.private_key {
                let ed_secret = &private.0; // Ed25519 private key (seed)

                // Properly hash and clamp the Ed25519 private key to get the X25519 private key
                use sha2::Digest;
                let hash = sha2::Sha512::digest(ed_secret);

                // Take the first 32 bytes of the hash
                let mut scalar_bytes = [0u8; 32];
                scalar_bytes.copy_from_slice(&hash[..32]);

                // Clamp the scalar as per RFC 7748
                scalar_bytes[0] &= 248;
                scalar_bytes[31] &= 127;
                scalar_bytes[31] |= 64;

                StaticSecret::from(scalar_bytes)
            } else {
                return Err(Error::JWK(didkit::ssi::jwk::Error::MissingPrivateKey));
            };

            Ok(mont_secret)
        }
        _ => Err(Error::JWK(didkit::ssi::jwk::Error::KeyTypeNotImplemented)),
    }
}

fn concat_kdf(secret: &[u8], key_len: u32, alg: &str, consumer_info: Option<&[u8]>) -> Vec<u8> {
    if key_len != 256 {
        panic!("Unsupported key length: {}", key_len);
    }

    // Helper for length and input
    fn length_and_input(input: &[u8]) -> Vec<u8> {
        let mut len_bytes = Vec::new();
        len_bytes
            .write_u32::<BigEndian>(input.len() as u32)
            .unwrap();
        [&len_bytes, input].concat()
    }

    // Build value array
    let mut value = Vec::new();
    value.extend(length_and_input(alg.as_bytes()));
    value.extend(length_and_input(&[])); // Empty producer info
    value.extend(length_and_input(consumer_info.unwrap_or(&[])));

    let mut key_len_bytes = Vec::new();
    key_len_bytes.write_u32::<BigEndian>(key_len).unwrap();
    value.extend(key_len_bytes);

    // Write round number (1)
    let mut round_bytes = Vec::new();
    round_bytes.write_u32::<BigEndian>(1).unwrap();

    // Final concatenation and hash
    let mut input = Vec::new();
    input.extend(round_bytes);
    input.extend(secret);
    input.extend(value);

    sha2::Sha256::digest(&input).to_vec()
}

// Decode a Multibase-encoded multikey for X25519 public keys.
// Accepts strings like "z..." (base58btc). Expects multicodec prefix x25519-pub (0xEC).
fn decode_public_key_multibase(mb: &str) -> Option<Vec<u8>> {
    // Only support base58btc ('z') for now
    let mut chars = mb.chars();
    let prefix = chars.next()?;
    if prefix != 'z' {
        return None;
    }

    let b58 = &mb[1..];
    let bytes = bs58::decode(b58).into_vec().ok()?;

    // Decode multicodec varint prefix
    let (code, remainder) = unsigned_varint::decode::u64(&bytes).ok()?;
    // 0xEC is x25519-pub
    if code != 0xEC {
        return None;
    }

    let key_bytes = remainder.to_vec();
    if key_bytes.len() == 32 {
        Some(key_bytes)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use didkit::Source;

    #[tokio::test]
    async fn test_encryption() -> Result<(), Error> {
        let sender = JWK::generate_ed25519()?;
        let receiver = JWK::generate_ed25519()?;
        let third_party = JWK::generate_ed25519()?;

        let receiver_did = DID_METHODS
            .generate(&Source::KeyAndPattern(&receiver, "key"))
            .ok_or(Error::UnableToGenerateDID)?;

        let content = b"Hello, DAG JWE!";

        // Test with random encryption
        let jwe = JWE::encrypt(content, &[receiver_did.clone()]).await?;

        let decrypted = &jwe.decrypt(&[receiver.clone()]).unwrap();

        assert_eq!(decrypted.as_slice(), content);

        let not_decrypted = &jwe.decrypt(&[sender.clone()]);

        assert!(not_decrypted.is_none());

        let not_decrypted_by_third_party = &jwe.decrypt(&[third_party.clone()]);

        assert!(not_decrypted_by_third_party.is_none());

        let decrypted_with_multiple_jwks = &jwe.decrypt(&[receiver, sender, third_party]).unwrap();

        assert_eq!(decrypted_with_multiple_jwks.as_slice(), content);

        Ok(())
    }

    #[tokio::test]
    async fn test_encryption_with_multiple_recipients() -> Result<(), Error> {
        let sender = JWK::generate_ed25519()?;
        let receiver = JWK::generate_ed25519()?;
        let third_party = JWK::generate_ed25519()?;

        let sender_did = DID_METHODS
            .generate(&Source::KeyAndPattern(&sender, "key"))
            .ok_or(Error::UnableToGenerateDID)?;
        let receiver_did = DID_METHODS
            .generate(&Source::KeyAndPattern(&receiver, "key"))
            .ok_or(Error::UnableToGenerateDID)?;

        let content = b"Hello, DAG JWE!";

        // Test with random encryption
        let jwe = JWE::encrypt(content, &[sender_did.clone(), receiver_did.clone()]).await?;

        let decrypted = &jwe.decrypt(&[receiver.clone()]).unwrap();

        assert_eq!(decrypted.as_slice(), content);

        let decrypted2 = &jwe.decrypt(&[sender.clone()]).unwrap();

        assert_eq!(decrypted2.as_slice(), content);

        let not_decrypted_by_third_party = &jwe.decrypt(&[third_party.clone()]);

        assert!(not_decrypted_by_third_party.is_none());

        let decrypted_with_multiple_jwks = &jwe.decrypt(&[receiver, sender, third_party]).unwrap();

        assert_eq!(decrypted_with_multiple_jwks.as_slice(), content);

        Ok(())
    }
}
