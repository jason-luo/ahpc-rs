use anyhow::{bail, Context};
use serde::Deserialize;

/// Client configuration matching the original client.json schema.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub proxy_server_address: String,
    pub proxy_server_port: u16,

    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    pub rsa_public_key: String,

    #[serde(default = "default_cipher")]
    pub cipher: String,

    #[serde(default = "default_timeout")]
    pub timeout: u64,

    #[serde(default = "default_workers")]
    pub workers: usize,

    #[serde(default)]
    pub auth_key: String,
}

fn default_bind_address() -> String {
    "127.0.0.1".into()
}
fn default_listen_port() -> u16 {
    8089
}
fn default_cipher() -> String {
    "aes-256-cfb".into()
}
fn default_timeout() -> u64 {
    240
}
fn default_workers() -> usize {
    2
}

/// Supported cipher modes and key lengths extracted from a normalized cipher name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Aes128Ofb,
    Aes192Ofb,
    Aes256Ofb,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
}

impl CipherKind {
    /// Parse from the user-facing cipher name, normalizing cfb/cfb128 etc.
    pub fn parse(name: &str) -> Option<CipherKind> {
        let lower = name.to_lowercase();
        let parts: Vec<&str> = lower.split('-').collect();
        if parts.len() != 3 || parts[0] != "aes" {
            return None;
        }
        let mode = if parts[2] == "cfb" || parts[2] == "cfb128" {
            "cfb"
        } else if parts[2] == "ofb" || parts[2] == "ofb128" {
            "ofb"
        } else if parts[2] == "ctr" || parts[2] == "ctr128" {
            "ctr"
        } else {
            return None;
        };
        match (parts[1], mode) {
            ("128", "cfb") => Some(CipherKind::Aes128Cfb),
            ("192", "cfb") => Some(CipherKind::Aes192Cfb),
            ("256", "cfb") => Some(CipherKind::Aes256Cfb),
            ("128", "ofb") => Some(CipherKind::Aes128Ofb),
            ("192", "ofb") => Some(CipherKind::Aes192Ofb),
            ("256", "ofb") => Some(CipherKind::Aes256Ofb),
            ("128", "ctr") => Some(CipherKind::Aes128Ctr),
            ("192", "ctr") => Some(CipherKind::Aes192Ctr),
            ("256", "ctr") => Some(CipherKind::Aes256Ctr),
            _ => None,
        }
    }

    /// The cipher code byte sent in the handshake protocol.
    pub fn code(self) -> u8 {
        match self {
            CipherKind::Aes128Cfb => 0x00,
            CipherKind::Aes192Cfb => 0x05,
            CipherKind::Aes256Cfb => 0x0A,
            CipherKind::Aes128Ofb => 0x03,
            CipherKind::Aes192Ofb => 0x08,
            CipherKind::Aes256Ofb => 0x0D,
            CipherKind::Aes128Ctr => 0x04,
            CipherKind::Aes192Ctr => 0x09,
            CipherKind::Aes256Ctr => 0x0E,
        }
    }

    /// AES key size in bytes.
    pub fn key_len(self) -> usize {
        match self {
            CipherKind::Aes128Cfb
            | CipherKind::Aes128Ofb
            | CipherKind::Aes128Ctr => 16,
            CipherKind::Aes192Cfb
            | CipherKind::Aes192Ofb
            | CipherKind::Aes192Ctr => 24,
            CipherKind::Aes256Cfb
            | CipherKind::Aes256Ofb
            | CipherKind::Aes256Ctr => 32,
        }
    }
}

impl Config {
    pub fn validate(&self) -> anyhow::Result<()> {
        // Timeout floor: 30 seconds (matches C++ behavior)
        if self.timeout < 30 {
            bail!("timeout must be >= 30 seconds");
        }
        if self.workers < 1 || self.workers > 16 {
            bail!("workers must be 1..=16");
        }

        // Validate cipher name
        CipherKind::parse(&self.cipher)
            .with_context(|| format!("Unsupported cipher: {}", self.cipher))?;

        // Validate RSA public key by parsing it
        crate::crypto::parse_public_key(&self.rsa_public_key)
            .context("Invalid RSA public key")?;

        Ok(())
    }
}
