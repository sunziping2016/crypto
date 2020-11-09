use crate::mem::Zeroize;
use crate::hash::Md5;
use crate::streamcipher::Rc4;


/// Rc4Md5 Stream Cipher
#[derive(Clone)]
pub struct Rc4Md5 {
    cipher: Rc4,
}

impl Zeroize for Rc4Md5 {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
    }
}

impl Drop for Rc4Md5 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for Rc4Md5 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Rc4Md5").finish()
    }
}

impl Rc4Md5 {
    pub const MIN_KEY_LEN: usize =   1;        // In bytes
    pub const MAX_KEY_LEN: usize = usize::MAX;
    
    
    pub fn new(key: &[u8], salt: &[u8]) -> Self {
        let mut m = Md5::new();
        m.update(key);
        m.update(salt);

        let key = m.finalize();

        let cipher = Rc4::new(&key);

        Self { cipher }
    }

    pub fn encrypt_slice(&mut self, plaintext_and_ciphertext: &mut [u8]) {
        self.cipher.encrypt_slice(plaintext_and_ciphertext)
    }
    
    pub fn decrypt_slice(&mut self, ciphertext_and_plaintext: &mut [u8]) {
        self.cipher.decrypt_slice(ciphertext_and_plaintext)
    }
}


#[test]
fn test_rc4_md5() {
    let key: &[u8]       = b"key";
    let nonce: &[u8]     = b"abcdefg123";
    let plaintext: &[u8] = b"abcd1234";

    let mut ciphertext = plaintext.to_vec();
    let mut cipher = Rc4Md5::new(key, nonce);
    cipher.encrypt_slice(&mut ciphertext);

    let mut cleartext = ciphertext.clone();
    let mut cipher = Rc4Md5::new(key, nonce);
    cipher.decrypt_slice(&mut cleartext);
    
    assert_eq!(&cleartext[..], plaintext);
}
