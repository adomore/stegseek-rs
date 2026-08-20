//! Adapters wrapping RustCrypto block ciphers in our `BlockCipher` trait.
//! Every wrapped cipher is still validated against libmcrypt golden vectors,
//! so this is purely an implementation shortcut for the standard ciphers.

use super::BlockCipher;
use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit};

pub struct Rc<C>(pub C);

impl<C> BlockCipher for Rc<C>
where
    C: BlockEncrypt + BlockDecrypt + BlockSizeUser,
{
    fn block_size(&self) -> usize {
        <C as BlockSizeUser>::block_size()
    }
    fn encrypt_block(&self, b: &mut [u8]) {
        let mut ga = GenericArray::clone_from_slice(b);
        self.0.encrypt_block(&mut ga);
        b.copy_from_slice(&ga);
    }
    fn decrypt_block(&self, b: &mut [u8]) {
        let mut ga = GenericArray::clone_from_slice(b);
        self.0.decrypt_block(&mut ga);
        b.copy_from_slice(&ga);
    }
}

/// Wraps a RustCrypto cipher that loads words big-endian (RFC order) so it
/// matches libmcrypt, which loads block/key words little-endian on x86.
/// Each 4-byte word of the block is reversed before and after the operation.
pub struct WordSwap<C>(pub C);
fn swap_words(b: &mut [u8]) {
    for w in b.chunks_mut(4) {
        w.reverse();
    }
}
impl<C> BlockCipher for WordSwap<C>
where
    C: BlockEncrypt + BlockDecrypt + BlockSizeUser,
{
    fn block_size(&self) -> usize {
        <C as BlockSizeUser>::block_size()
    }
    fn encrypt_block(&self, b: &mut [u8]) {
        swap_words(b);
        let mut ga = GenericArray::clone_from_slice(b);
        self.0.encrypt_block(&mut ga);
        b.copy_from_slice(&ga);
        swap_words(b);
    }
    fn decrypt_block(&self, b: &mut [u8]) {
        swap_words(b);
        let mut ga = GenericArray::clone_from_slice(b);
        self.0.decrypt_block(&mut ga);
        b.copy_from_slice(&ga);
        swap_words(b);
    }
}

/// Byte-swap each 4-byte word of a key (mcrypt loads key words little-endian).
fn key_swap_words(key: &[u8]) -> Vec<u8> {
    let mut k = key.to_vec();
    swap_words(&mut k);
    k
}

/// Construct a wrapped RustCrypto cipher by name; `None` if not handled here.
pub fn build(name: &str, key: &[u8]) -> Option<Box<dyn BlockCipher>> {
    match name {
        "des" => Some(Box::new(Rc(des::Des::new_from_slice(key).ok()?))),
        "tripledes" => Some(Box::new(Rc(des::TdesEde3::new_from_slice(key).ok()?))),
        "twofish" => Some(Box::new(Rc(twofish::Twofish::new_from_slice(key).ok()?))),
        "serpent" => Some(Box::new(Rc(serpent::Serpent::new_from_slice(key).ok()?))),
        "blowfish" => Some(Box::new(Rc(
            blowfish::Blowfish::<byteorder::BE>::new_from_slice(key).ok()?,
        ))),
        "cast-128" => Some(Box::new(Rc(cast5::Cast5::new_from_slice(key).ok()?))),
        "cast-256" => {
            let k = key_swap_words(key);
            Some(Box::new(WordSwap(cast6::Cast6::new_from_slice(&k).ok()?)))
        }
        "rc2" => Some(Box::new(Rc(rc2::Rc2::new_from_slice(key).ok()?))),
        _ => None,
    }
}
