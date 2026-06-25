use crate::config::CipherKind;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use anyhow::Context;
use rand::RngCore;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPublicKey};
use sha1::Sha1;

pub fn parse_public_key(pem: &str) -> anyhow::Result<RsaPublicKey> {
    use rsa::pkcs8::DecodePublicKey;
    let key =
        RsaPublicKey::from_public_key_pem(pem).context("Failed to parse RSA public key PEM")?;
    anyhow::ensure!(key.size() >= 128, "RSA key must be at least 1024 bits");
    Ok(key)
}

pub fn rsa_encrypt(pub_key: &RsaPublicKey, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let padding = Oaep::new::<Sha1>();
    pub_key
        .encrypt(&mut rng, padding, data)
        .context("RSA encryption failed")
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

// ── CFB-128 — byte-level feedback (matches mbedtls) ──

pub struct Cfb128<A: BlockEncrypt + KeyInit> {
    cipher: A,
    feedback: [u8; 16],
    ks_pos: usize,
}

impl<A: BlockEncrypt + KeyInit> Cfb128<A> {
    pub fn new(key: &[u8], iv: &[u8; 16]) -> Self {
        Self {
            cipher: A::new(GenericArray::from_slice(key)),
            feedback: *iv,
            ks_pos: 0,
        }
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.ks_pos == 0 {
                self.cipher
                    .encrypt_block(GenericArray::from_mut_slice(&mut self.feedback));
            }
            let ct = self.feedback[self.ks_pos] ^ *byte;
            self.feedback[self.ks_pos] = ct;
            *byte = ct;
            self.ks_pos = (self.ks_pos + 1) & 0x0F;
        }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.ks_pos == 0 {
                self.cipher
                    .encrypt_block(GenericArray::from_mut_slice(&mut self.feedback));
            }
            let ct = *byte;
            *byte ^= self.feedback[self.ks_pos];
            self.feedback[self.ks_pos] = ct;
            self.ks_pos = (self.ks_pos + 1) & 0x0F;
        }
    }
}

// ── OFB — Output Feedback (matches mbedtls `mbedtls_aes_crypt_ofb`) ──
//
// Keystream: encrypt_iv → keystream[0..15], then re-encrypt iv every 16 bytes.
// Both encrypt and decrypt XOR plaintext/ciphertext with keystream.

pub struct Ofb<A: BlockEncrypt + KeyInit> {
    cipher: A,
    iv: [u8; 16],
    ks_pos: usize,
}

impl<A: BlockEncrypt + KeyInit> Ofb<A> {
    pub fn new(key: &[u8], iv: &[u8; 16]) -> Self {
        Self {
            cipher: A::new(GenericArray::from_slice(key)),
            iv: *iv,
            ks_pos: 0,
        }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.ks_pos == 0 {
                self.cipher
                    .encrypt_block(GenericArray::from_mut_slice(&mut self.iv));
            }
            *byte ^= self.iv[self.ks_pos];
            self.ks_pos = (self.ks_pos + 1) & 0x0F;
        }
    }
}

// ── CTR — Counter mode (matches mbedtls `mbedtls_aes_crypt_ctr`) ──
//
// Counter: 16-byte big-endian, encrypted every 16 bytes then incremented.
// Both encrypt and decrypt are identical.

pub struct Ctr<A: BlockEncrypt + KeyInit> {
    cipher: A,
    counter: [u8; 16],
    stream: [u8; 16],
    ks_pos: usize,
}

impl<A: BlockEncrypt + KeyInit> Ctr<A> {
    pub fn new(key: &[u8], iv: &[u8; 16]) -> Self {
        Self {
            cipher: A::new(GenericArray::from_slice(key)),
            counter: *iv,
            stream: [0u8; 16],
            ks_pos: 16, // trigger initial encrypt
        }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.ks_pos == 16 {
                // Copy counter, encrypt copy → stream_block.
                // mbedtls uses separate in/out for ECB, RustCrypto encrypts in-place.
                let mut block = self.counter;
                self.cipher
                    .encrypt_block(GenericArray::from_mut_slice(&mut block));
                self.stream = block;
                // Increment the ORIGINAL counter (big-endian)
                for i in (0..16).rev() {
                    self.counter[i] = self.counter[i].wrapping_add(1);
                    if self.counter[i] != 0 {
                        break;
                    }
                }
                self.ks_pos = 0;
            }
            *byte ^= self.stream[self.ks_pos];
            self.ks_pos += 1;
        }
    }
}

// ── Unified Cipher enum ──

pub enum Cipher {
    Cfb128Aes128(Cfb128<Aes128>),
    Cfb128Aes192(Cfb128<Aes192>),
    Cfb128Aes256(Cfb128<Aes256>),
    OfbAes128(Ofb<Aes128>),
    OfbAes192(Ofb<Aes192>),
    OfbAes256(Ofb<Aes256>),
    CtrAes128(Ctr<Aes128>),
    CtrAes192(Ctr<Aes192>),
    CtrAes256(Ctr<Aes256>),
}

impl Cipher {
    pub fn encrypt(&mut self, data: &mut [u8]) {
        match self {
            Self::Cfb128Aes128(c) => c.encrypt(data),
            Self::Cfb128Aes192(c) => c.encrypt(data),
            Self::Cfb128Aes256(c) => c.encrypt(data),
            Self::OfbAes128(c) => c.apply(data),
            Self::OfbAes192(c) => c.apply(data),
            Self::OfbAes256(c) => c.apply(data),
            Self::CtrAes128(c) => c.apply(data),
            Self::CtrAes192(c) => c.apply(data),
            Self::CtrAes256(c) => c.apply(data),
        }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        match self {
            Self::Cfb128Aes128(c) => c.decrypt(data),
            Self::Cfb128Aes192(c) => c.decrypt(data),
            Self::Cfb128Aes256(c) => c.decrypt(data),
            Self::OfbAes128(c) => c.apply(data),
            Self::OfbAes192(c) => c.apply(data),
            Self::OfbAes256(c) => c.apply(data),
            Self::CtrAes128(c) => c.apply(data),
            Self::CtrAes192(c) => c.apply(data),
            Self::CtrAes256(c) => c.apply(data),
        }
    }
}

pub struct CipherPair {
    pub encryptor: Cipher,
    pub decryptor: Cipher,
}

/// For CTR mode the C++ client uses all‑zero IV.  We replicate that.
fn iv_for_mode(kind: CipherKind, iv: &[u8; 16]) -> [u8; 16] {
    match kind {
        CipherKind::Aes128Ctr
        | CipherKind::Aes192Ctr
        | CipherKind::Aes256Ctr => [0u8; 16],
        _ => *iv,
    }
}

pub fn create_cipher_pair(kind: CipherKind, key: &[u8], iv: &[u8]) -> anyhow::Result<CipherPair> {
    let iv16: &[u8; 16] = iv.try_into().context("IV must be exactly 16 bytes")?;
    let ctr_iv = iv_for_mode(kind, iv16);

    macro_rules! cfb {
        ($aes:ty, $enc:expr, $dec:expr) => {{
            CipherPair {
                encryptor: $enc(Cfb128::<$aes>::new(key, iv16)),
                decryptor: $dec(Cfb128::<$aes>::new(key, iv16)),
            }
        }};
    }

    macro_rules! single {
        ($aes:ty, $wrap:ty, $enc:expr, $dec:expr) => {{
            CipherPair {
                encryptor: $enc(<$wrap>::new(key, &ctr_iv)),
                decryptor: $dec(<$wrap>::new(key, &ctr_iv)),
            }
        }};
    }

    Ok(match kind {
        CipherKind::Aes128Cfb => cfb!(Aes128, Cipher::Cfb128Aes128, Cipher::Cfb128Aes128),
        CipherKind::Aes192Cfb => cfb!(Aes192, Cipher::Cfb128Aes192, Cipher::Cfb128Aes192),
        CipherKind::Aes256Cfb => cfb!(Aes256, Cipher::Cfb128Aes256, Cipher::Cfb128Aes256),
        CipherKind::Aes128Ofb => single!(Aes128, Ofb<Aes128>, Cipher::OfbAes128, Cipher::OfbAes128),
        CipherKind::Aes192Ofb => single!(Aes192, Ofb<Aes192>, Cipher::OfbAes192, Cipher::OfbAes192),
        CipherKind::Aes256Ofb => single!(Aes256, Ofb<Aes256>, Cipher::OfbAes256, Cipher::OfbAes256),
        CipherKind::Aes128Ctr => single!(Aes128, Ctr<Aes128>, Cipher::CtrAes128, Cipher::CtrAes128),
        CipherKind::Aes192Ctr => single!(Aes192, Ctr<Aes192>, Cipher::CtrAes192, Cipher::CtrAes192),
        CipherKind::Aes256Ctr => single!(Aes256, Ctr<Aes256>, Cipher::CtrAes256, Cipher::CtrAes256),
    })
}
