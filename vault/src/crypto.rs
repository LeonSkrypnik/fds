use argon2::{password_hash::SaltString, Argon2, Params, PasswordHasher};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

pub const KEY_LEN: usize = 32;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

pub fn derive_kek_argon2id(
    password: &str,
    salt: &[u8; 16],
    m_cost_kib: u32,
    t_cost: u32,
) -> anyhow::Result<[u8; KEY_LEN]> {
    let params = Params::new(m_cost_kib, t_cost, 1, Some(KEY_LEN))
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    );

    // PasswordHasher API expects a SaltString; we pass raw salt as base64-like string.
    // To keep file format stable we store salt raw in header.
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("salt encode: {e}"))?;

    let mut out = [0u8; KEY_LEN];
    let hash = argon2
        .hash_password_customized(password.as_bytes(), None, None, params, &salt_string)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;

    // Convert PHC string into raw bytes via HKDF to avoid relying on internal argon2 output format.
    // (MVP: stable derivation; for production you'd use argon2 low-level API to get raw output.)
    let hk = Hkdf::<Sha256>::new(
        None,
        hash.hash
            .ok_or_else(|| anyhow::anyhow!("argon2 missing hash"))?
            .as_bytes(),
    );
    hk.expand(b"vault-kek", &mut out)
        .map_err(|e| anyhow::anyhow!("hkdf expand: {e}"))?;
    Ok(out)
}

pub fn aead_encrypt(
    key: &[u8; KEY_LEN],
    nonce12: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce12);
    let out = cipher.encrypt(nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })?;
    Ok(out)
}

pub fn aead_decrypt(
    key: &[u8; KEY_LEN],
    nonce12: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce12);
    let out = cipher.decrypt(nonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad })?;
    Ok(out)
}

pub fn hkdf_derive(master_key: &[u8; KEY_LEN], info: &[u8]) -> anyhow::Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out)
        .map_err(|e| anyhow::anyhow!("hkdf expand: {e}"))?;
    Ok(out)
}

pub fn zeroize_vec(mut v: Vec<u8>) {
    v.zeroize();
}