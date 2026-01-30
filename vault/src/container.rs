use crate::crypto::{aead_decrypt, aead_encrypt, hkdf_derive, random_bytes, KEY_LEN};
use crate::fsmeta::{ChunkRef, Metadata, NodeType};
use anyhow::Context;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"VLT1";
const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub magic: [u8; 4],
    pub version: u32,

    // KDF params
    pub kdf_m_cost_kib: u32,
    pub kdf_t_cost: u32,
    pub salt: [u8; 16],

    // wrapped master key
    pub mk_wrap_nonce: [u8; 12],
    pub wrapped_master_key: Vec<u8>,

    // encrypted metadata
    pub meta_nonce: [u8; 12],
    pub meta_len: u32,
    pub meta_cipher: Vec<u8>,
}

#[derive(Debug)]
pub struct Session {
    pub path: String,
    pub master_key: [u8; KEY_LEN],
    pub meta: Metadata,
}

fn header_aad(h: &Header) -> Vec<u8> {
    // AAD: stable subset of header fields (no ciphertexts). MVP.
    let mut aad = Vec::new();
    aad.extend_from_slice(&h.magic);
    aad.extend_from_slice(&h.version.to_le_bytes());
    aad.extend_from_slice(&h.kdf_m_cost_kib.to_le_bytes());
    aad.extend_from_slice(&h.kdf_t_cost.to_le_bytes());
    aad.extend_from_slice(&h.salt);
    aad.extend_from_slice(&h.mk_wrap_nonce);
    aad
}

pub fn create_vault(path: &str, password: &str, m_cost_kib: u32, t_cost: u32) -> anyhow::Result<()> {
    let salt = random_bytes::<16>();
    let kek = crate::crypto::derive_kek_argon2id(password, &salt, m_cost_kib, t_cost)?;

    let master_key = random_bytes::<KEY_LEN>();

    let mut header = Header {
        magic: *MAGIC,
        version: VERSION,
        kdf_m_cost_kib: m_cost_kib,
        kdf_t_cost: t_cost,
        salt,
        mk_wrap_nonce: random_bytes::<12>(),
        wrapped_master_key: vec![],
        meta_nonce: random_bytes::<12>(),
        meta_len: 0,
        meta_cipher: vec![],
    };

    let aad = header_aad(&header);
    header.wrapped_master_key = aead_encrypt(&kek, &header.mk_wrap_nonce, &aad, &master_key)?;

    let meta = Metadata::new_empty();
    let meta_plain = serde_cbor::to_vec(&meta)?;
    header.meta_cipher = aead_encrypt(&master_key, &header.meta_nonce, &aad, &meta_plain)?;
    header.meta_len = header.meta_cipher.len() as u32;

    // Layout: [u32 header_len][cbor(header)][data...]
    let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(path)?;
    let header_bytes = serde_cbor::to_vec(&header)?;
    f.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    f.write_all(&header_bytes)?;
    f.flush()?;
    Ok(())
}

pub fn open_vault(path: &str, password: &str) -> anyhow::Result<Session> {
    let mut f = File::open(path).with_context(|| format!("open {path}"))?;

    let mut len4 = [0u8; 4];
    f.read_exact(&mut len4)?;
    let header_len = u32::from_le_bytes(len4) as usize;

    let mut header_buf = vec![0u8; header_len];
    f.read_exact(&mut header_buf)?;
    let header: Header = serde_cbor::from_slice(&header_buf)?;

    if &header.magic != MAGIC {
        anyhow::bail!("bad magic");
    }
    if header.version != VERSION {
        anyhow::bail!("unsupported version {}", header.version);
    }

    let kek = crate::crypto::derive_kek_argon2id(password, &header.salt, header.kdf_m_cost_kib, header.kdf_t_cost)?;
    let aad = header_aad(&header);
    let mk_plain = aead_decrypt(&kek, &header.mk_wrap_nonce, &aad, &header.wrapped_master_key)
        .context("wrong password or corrupted header")?;

    if mk_plain.len() != KEY_LEN {
        anyhow::bail!("invalid master key length");
    }
    let mut master_key = [0u8; KEY_LEN];
    master_key.copy_from_slice(&mk_plain);

    let meta_plain = aead_decrypt(&master_key, &header.meta_nonce, &aad, &header.meta_cipher)
        .context("metadata auth failed (wrong password or corrupted vault)")?;
    let meta: Metadata = serde_cbor::from_slice(&meta_plain)?;

    Ok(Session {
        path: path.to_string(),
        master_key,
        meta,
    })
}

pub fn save_metadata(sess: &Session, password: &str) -> anyhow::Result<()> {
    // Re-read header, unwrap MK again (MVP: keeps format simple)
    let mut f = OpenOptions::new().read(true).write(true).open(&sess.path)?;

    let mut len4 = [0u8; 4];
    f.read_exact(&mut len4)?;
    let header_len = u32::from_le_bytes(len4) as usize;

    let mut header_buf = vec![0u8; header_len];
    f.read_exact(&mut header_buf)?;
    let mut header: Header = serde_cbor::from_slice(&header_buf)?;

    let kek = crate::crypto::derive_kek_argon2id(password, &header.salt, header.kdf_m_cost_kib, header.kdf_t_cost)?;
    let aad = header_aad(&header);
    let mk_plain = aead_decrypt(&kek, &header.mk_wrap_nonce, &aad, &header.wrapped_master_key)?;

    if mk_plain.len() != KEY_LEN {
        anyhow::bail!("invalid master key length");
    }
    if mk_plain.as_slice() != sess.master_key.as_slice() {
        // defensive: shouldn't happen
        anyhow::bail!("master key mismatch");
    }

    let meta_plain = serde_cbor::to_vec(&sess.meta)?;
    header.meta_nonce = random_bytes::<12>();
    header.meta_cipher = aead_encrypt(&sess.master_key, &header.meta_nonce, &aad, &meta_plain)?;
    header.meta_len = header.meta_cipher.len() as u32;

    let new_header_bytes = serde_cbor::to_vec(&header)?;

    // Rewrite whole file (MVP, no journaling): write to temp and rename.
    let tmp_path = format!("{}.tmp", sess.path);
    {
        let mut tmp = OpenOptions::new().create(true).truncate(true).write(true).open(&tmp_path)?;
        tmp.write_all(&(new_header_bytes.len() as u32).to_le_bytes())?;
        tmp.write_all(&new_header_bytes)?;

        // Copy data region verbatim (everything after old header)
        f.seek(SeekFrom::Start(4 + header_len as u64))?;
        std::io::copy(&mut f, &mut tmp)?;
        tmp.flush()?;
    }
    std::fs::rename(tmp_path, &sess.path)?;
    Ok(())
}

pub fn import_file(sess: &mut Session, password: &str, os_path: &Path, parent_id: u64, name_in_vault: Option<String>) -> anyhow::Result<u64> {
    let name = name_in_vault
        .or_else(|| os_path.file_name().map(|s| s.to_string_lossy().to_string()))
        .ok_or_else(|| anyhow::anyhow!("cannot determine filename"))?;

    let mut src = File::open(os_path)?;
    let size = src.metadata()?.len();

    // Open vault file and seek to end for append (MVP: no freelist reuse)
    let mut vf = OpenOptions::new().read(true).write(true).open(&sess.path)?;

    // Parse header len to compute data start, then seek end
    let mut len4 = [0u8; 4];
    vf.read_exact(&mut len4)?;
    let header_len = u32::from_le_bytes(len4) as u64;
    vf.seek(SeekFrom::Start(4 + header_len))?;
    let data_start = vf.stream_position()?;
    vf.seek(SeekFrom::End(0))?;

    let file_id = sess.meta.alloc_id();
    let file_key = hkdf_derive(&sess.master_key, format!("file:{file_id}").as_bytes())?;

    let mut chunks: Vec<ChunkRef> = vec![];
    let mut buf = vec![0u8; 1024 * 1024]; // 1 MiB
    let mut idx: u32 = 0;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        idx += 1;
        let chunk_key = hkdf_derive(&file_key, format!("chunk:{idx}").as_bytes())?;
        let nonce = crate::crypto::random_bytes::<12>();
        let aad = format!("{file_id}:{idx}").into_bytes();
        let cipher = aead_encrypt(&chunk_key, &nonce, &aad, &buf[..n])?;

        let offset = vf.stream_position()?;
        vf.write_all(&cipher)?;
        chunks.push(ChunkRef {
            index: idx,
            offset: offset - data_start,
            len: cipher.len() as u32,
            nonce,
        });
    }
    vf.flush()?;

    // record in metadata
    sess.meta.nodes.push(crate::fsmeta::Node {
        id: file_id,
        parent_id,
        node_type: NodeType::File,
        name,
        size,
        chunks,
    });

    save_metadata(sess, password)?;
    Ok(file_id)
}

pub fn export_file(sess: &Session, file_id: u64, out_path: &Path) -> anyhow::Result<()> {
    let n = sess.meta.get_node(file_id).ok_or_else(|| anyhow::anyhow!("not found"))?;
    if n.node_type != NodeType::File {
        anyhow::bail!("not a file");
    }

    let mut vf = File::open(&sess.path)?;
    let mut len4 = [0u8; 4];
    vf.read_exact(&mut len4)?;
    let header_len = u32::from_le_bytes(len4) as u64;
    vf.seek(SeekFrom::Start(4 + header_len))?;
    let data_start = vf.stream_position()?;

    let file_key = hkdf_derive(&sess.master_key, format!("file:{file_id}").as_bytes())?;

    let mut out = OpenOptions::new().create(true).truncate(true).write(true).open(out_path)?;

    for ch in &n.chunks {
        let chunk_key = hkdf_derive(&file_key, format!("chunk:{}", ch.index).as_bytes())?;
        let aad = format!("{file_id}:{}", ch.index).into_bytes();

        vf.seek(SeekFrom::Start(data_start + ch.offset))?;
        let mut cipher = vec![0u8; ch.len as usize];
        vf.read_exact(&mut cipher)?;
        let plain = aead_decrypt(&chunk_key, &ch.nonce, &aad, &cipher)?;
        out.write_all(&plain)?;
    }
    out.flush()?;
    Ok(())
}

impl Drop for Session {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}