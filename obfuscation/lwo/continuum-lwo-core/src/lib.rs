//! Mullvad-compatible LWO (Lightweight WireGuard Obfuscation) codec.

use rand::RngCore;
use thiserror::Error;

const MAX_UDP_SIZE: usize = u16::MAX as usize;

type MessageType = u8;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

/// Bit set in the second byte of the WG header to mark LWO obfuscation.
const OBFUSCATION_BIT: u8 = 0b10000000;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid WireGuard public key (expected base64, 32 bytes decoded)")]
    InvalidPublicKey,
}

/// Decode a WireGuard base64 public key to 32 bytes.
pub fn decode_public_key(b64: &str) -> Result<[u8; 32], KeyError> {
    let trimmed = b64.trim();
    let decoded = base64_decode(trimmed).map_err(|_| KeyError::InvalidPublicKey)?;
    if decoded.len() != 32 {
        return Err(KeyError::InvalidPublicKey);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    const TABLE: [i8; 256] = {
        let mut t = [-1i8; 256];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < chars.len() {
            t[chars[i] as usize] = i as i8;
            i += 1;
        }
        t
    };

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &byte in input.as_bytes() {
        if byte == b'=' {
            break;
        }
        let val = TABLE[byte as usize];
        if val < 0 {
            continue;
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

pub fn obfuscate(rng: &mut impl RngCore, packet: &mut [u8], key: &[u8; 32]) {
    let Some(header_bytes) = header_mut(packet, 0) else {
        return;
    };

    xor_bytes(header_bytes, key);
    let rand_byte = (rng.next_u32() % u8::MAX as u32) as u8;
    header_bytes[1] = rand_byte | OBFUSCATION_BIT;
}

pub fn deobfuscate(packet: &mut [u8], key: &[u8; 32]) {
    let Some(header_bytes) = header_mut(packet, key[0]) else {
        return;
    };

    xor_bytes(header_bytes, key);
    header_bytes[1] = 0;
}

fn header_mut(packet: &mut [u8], key_byte: u8) -> Option<&mut [u8]> {
    let &header_type = packet.first()?;
    match header_type ^ key_byte {
        HANDSHAKE_INIT => packet.get_mut(..HANDSHAKE_INIT_SZ),
        HANDSHAKE_RESP => packet.get_mut(..HANDSHAKE_RESP_SZ),
        COOKIE_REPLY => packet.get_mut(..COOKIE_REPLY_SZ),
        DATA => packet.get_mut(..DATA_OVERHEAD_SZ),
        _ => None,
    }
}

fn xor_bytes(data: &mut [u8], key: &[u8; 32]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

pub fn relay_buf_size() -> usize {
    MAX_UDP_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn fake_packet() -> Vec<u8> {
        let mut packet = vec![0u8; DATA_OVERHEAD_SZ + 100];
        packet[0] = DATA;
        rand::rng().fill_bytes(&mut packet[DATA_OVERHEAD_SZ..]);
        packet
    }

    #[test]
    fn round_trip_obfuscation() {
        let key = [0xefu8; 32];
        let mut packet = fake_packet();
        let original = packet.clone();

        obfuscate(&mut rand::rng(), &mut packet, &key);
        assert_ne!(packet, original);
        assert_eq!(packet[DATA_OVERHEAD_SZ..], original[DATA_OVERHEAD_SZ..]);

        deobfuscate(&mut packet, &key);
        assert_eq!(packet, original);
    }

    #[test]
    fn decode_wg_public_key() {
        let key = decode_public_key("8Ka2l4T0tVrSR5pkcsvRG++mBlxfuf8XOxpqBkOCikU=").unwrap();
        assert_eq!(key.len(), 32);
    }
}
