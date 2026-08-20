//! Block/stream cipher abstractions and implementations.

pub mod enigma;
pub mod gost;
pub mod loki97;
pub mod rc;
pub mod rijndael;
pub mod saferplus;
pub mod stream;
pub mod wake;
pub mod xtea;

pub trait BlockCipher {
    fn block_size(&self) -> usize;
    fn encrypt_block(&self, block: &mut [u8]);
    fn decrypt_block(&self, block: &mut [u8]);
}

pub fn block_cipher_by_name(name: &str, key: &[u8]) -> Option<Box<dyn BlockCipher>> {
    match name {
        "rijndael-128" => Some(Box::new(rijndael::Rijndael::new(key, 16))),
        "rijndael-192" => Some(Box::new(rijndael::Rijndael::new(key, 24))),
        "rijndael-256" => Some(Box::new(rijndael::Rijndael::new(key, 32))),
        "xtea" => Some(Box::new(xtea::Xtea::new(key))),
        "saferplus" => Some(Box::new(saferplus::SaferPlus::new(key))),
        "loki97" => Some(Box::new(loki97::Loki97::new(key))),
        "gost" => Some(Box::new(gost::Gost::new(key))),
        _ => rc::build(name, key),
    }
}
