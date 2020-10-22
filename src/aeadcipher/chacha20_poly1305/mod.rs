use subtle;

use crate::streamcipher::Chacha20;


mod poly1305;
use self::poly1305::Poly1305;


/// ChaCha20 and Poly1305 for IETF Protocols
/// 
/// https://tools.ietf.org/html/rfc8439
#[derive(Debug, Clone)]
pub struct Chacha20Poly1305 {
    chacha20: Chacha20,
    poly1305: Poly1305,
}

impl Chacha20Poly1305 {
    pub const KEY_LEN: usize   = Chacha20::KEY_LEN;   // 32 bytes
    pub const BLOCK_LEN: usize = Chacha20::BLOCK_LEN; // 64 bytes
    pub const NONCE_LEN: usize = Chacha20::NONCE_LEN; // 12 bytes
    pub const TAG_LEN: usize   = Poly1305::TAG_LEN;   // 16 bytes

    #[cfg(target_pointer_width = "64")]
    pub const A_MAX: usize = u64::MAX as usize; // 2^64 - 1
    #[cfg(target_pointer_width = "32")]
    pub const A_MAX: usize = usize::MAX;        // 2^32 - 1

    pub const P_MAX: usize = 274877906880;                // (2^32 - 1) * BLOCK_LEN
    pub const C_MAX: usize = Self::P_MAX + Self::TAG_LEN; // 274,877,906,896
    
    pub const N_MIN: usize = Self::NONCE_LEN;
    pub const N_MAX: usize = Self::NONCE_LEN;

    const PADDING_BLOCK: [u8; Poly1305::BLOCK_LEN] = [0u8; Poly1305::BLOCK_LEN];


    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(Self::KEY_LEN, Poly1305::KEY_LEN);
        assert_eq!(key.len(), Self::KEY_LEN);
        assert_eq!(nonce.len(), Self::NONCE_LEN);

        let mut chacha20 = Chacha20::new(key, nonce);

        let mut keystream = [0u8; Self::BLOCK_LEN];
        chacha20.encrypt(&mut keystream); // Block Index: 1

        let mut keystream = [0u8; Self::BLOCK_LEN];
        chacha20.encrypt(&mut keystream); // Block Index: 2

        let mut poly1305_key = [0u8; Poly1305::KEY_LEN];
        poly1305_key.copy_from_slice(&keystream[..Poly1305::KEY_LEN][..]);

        let poly1305 = Poly1305::new(&poly1305_key[..]);
        
        Self { chacha20, poly1305, }
    }
    
    pub fn aead_encrypt(&mut self, aad: &[u8], plaintext_and_ciphertext: &mut [u8]) {
        debug_assert!(plaintext_and_ciphertext.len() >= Self::TAG_LEN);
        debug_assert!(plaintext_and_ciphertext.len() <= Self::C_MAX);
        debug_assert!(aad.len() <= Self::A_MAX);

        let alen = aad.len();
        let clen = plaintext_and_ciphertext.len();
        let plen = plaintext_and_ciphertext.len() - Self::TAG_LEN;

        let plaintext = &mut plaintext_and_ciphertext[..plen];
        let mut poly1305 = self.poly1305.clone();

        self.chacha20.encrypt(plaintext);

        poly1305.update(aad);
        // padding AAD
        let r = Poly1305::BLOCK_LEN - alen % Poly1305::BLOCK_LEN;
        if r > 0 {
            poly1305.update(&Self::PADDING_BLOCK[..r]);
        }

        poly1305.update(plaintext);
        // padding ciphertext
        let r = Poly1305::BLOCK_LEN - plen % Poly1305::BLOCK_LEN;
        if r > 0 {
            poly1305.update(&Self::PADDING_BLOCK[..r]);
        }

        poly1305.update(&(alen as u64).to_le_bytes());
        poly1305.update(&(plen as u64).to_le_bytes());

        let tag = poly1305.finalize();

        // Append TAG.
        plaintext_and_ciphertext[plen..plen + Self::TAG_LEN].copy_from_slice(&tag);
    }

    pub fn aead_decrypt(&mut self, aad: &[u8], ciphertext_and_plaintext: &mut [u8]) -> bool {
        debug_assert!(ciphertext_and_plaintext.len() >= Self::TAG_LEN);
        debug_assert!(ciphertext_and_plaintext.len() <= Self::C_MAX);
        debug_assert!(aad.len() <= Self::A_MAX);

        let alen = aad.len();
        let clen = ciphertext_and_plaintext.len();
        let plen = ciphertext_and_plaintext.len() - Self::TAG_LEN;

        let ciphertext = &ciphertext_and_plaintext[..plen];
        let mut poly1305 = self.poly1305.clone();

        poly1305.update(aad);
        // padding AAD
        let r = Poly1305::BLOCK_LEN - alen % Poly1305::BLOCK_LEN;
        if r > 0 {
            poly1305.update(&Self::PADDING_BLOCK[..r]);
        }

        poly1305.update(&ciphertext);
        // padding ciphertext
        let r = Poly1305::BLOCK_LEN - plen % Poly1305::BLOCK_LEN;
        if r > 0 {
            poly1305.update(&Self::PADDING_BLOCK[..r]);
        }

        poly1305.update(&(alen as u64).to_le_bytes());
        poly1305.update(&(plen as u64).to_le_bytes());

        let tag = poly1305.finalize();

        // Verify
        let input_tag = &ciphertext_and_plaintext[plen..plen + Self::TAG_LEN];
        let is_match = bool::from(subtle::ConstantTimeEq::ct_eq(&input_tag[..], &tag[..]));

        if is_match {
            let ciphertext = &mut ciphertext_and_plaintext[..plen];
            self.chacha20.decrypt(ciphertext);
        }

        is_match
    }
}


// chacha20-poly1305@openssh.com
// 
// http://bxr.su/OpenBSD/usr.bin/ssh/PROTOCOL.chacha20poly1305
// https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-03
// 
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/PROTOCOL.chacha20poly1305
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/chacha.c
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/chacha.h
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/poly1305.c
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/poly1305.h
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/cipher-chachapoly.c
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/cipher-chachapoly.h
// https://github.com/openbsd/src/blob/master/usr.bin/ssh/cipher-chachapoly-libcrypto.c
// 
// 
// Code:
// http://bxr.su/OpenBSD/usr.bin/ssh/chacha.c
// http://bxr.su/OpenBSD/usr.bin/ssh/chacha.h
// http://bxr.su/OpenBSD/usr.bin/ssh/poly1305.c
// http://bxr.su/OpenBSD/usr.bin/ssh/poly1305.h
// http://bxr.su/OpenBSD/usr.bin/ssh/cipher-chachapoly.c
// http://bxr.su/OpenBSD/usr.bin/ssh/cipher-chachapoly.h
// #[derive(Debug, Clone)]
// pub struct Chacha20Poly1305OpenSSH {
//     chacha20: Chacha20,
//     poly1305: Poly1305,
//     data_len: usize,
// }

#[test]
fn test_poly1305_key_generation() {
    // 2.6.2.  Poly1305 Key Generation Test Vector
    // https://tools.ietf.org/html/rfc8439#section-2.6.2
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 
        0x04, 0x05, 0x06, 0x07 
    ];

    let mut chacha20 = Chacha20::new(&key, &nonce);

    let mut keystream = [0u8; Chacha20::BLOCK_LEN];
    chacha20.encrypt(&mut keystream); // Block Index: 1
    let mut keystream = [0u8; Chacha20::BLOCK_LEN];
    chacha20.encrypt(&mut keystream); // Block Index: 2

    assert_eq!(&keystream[..Poly1305::KEY_LEN], &[
        0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 
        0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2, 0x94, 0x71,
        0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 
        0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46,
    ]);
}

#[test]
fn test_aead_chacha20_poly1305_encrypt() {
    // 2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305
    // https://tools.ietf.org/html/rfc8439#section-2.8.2
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    let aad = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 
        0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce = [
        0x07, 0x00, 0x00, 0x00,                         // Constants
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, // IV
    ];

    let mut chacha20_poly1305 = Chacha20Poly1305::new(&key, &nonce);

    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.to_vec();
    ciphertext_and_tag.resize(plen + Chacha20Poly1305::TAG_LEN, 0);
    
    chacha20_poly1305.aead_encrypt(&aad, &mut ciphertext_and_tag);

    assert_eq!(&ciphertext_and_tag[..], &[
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
        // TAG
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ][..]);
}

#[test]
fn test_aead_chacha20_poly1305_decrypt() {
    // A.5.  ChaCha20-Poly1305 AEAD Decryption
    // https://tools.ietf.org/html/rfc8439#appendix-A.5
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [
        0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x4e, 0x91,
    ];
    
    let plaintext = b"Internet-Drafts are draft documents valid for a \
maximum of six months and may be updated, replaced, or obsoleted \
by other documents at any time. It is inappropriate to use Internet-Drafts as \
reference material or to cite them other than as \x2f\xe2\x80\x9c\
work in progress.\x2f\xe2\x80\x9d";
    
    let plen = plaintext.len();
    let mut ciphertext_and_tag = plaintext.to_vec();
    ciphertext_and_tag.resize(plen + Chacha20Poly1305::TAG_LEN, 0);

    let mut chacha20_poly1305 = Chacha20Poly1305::new(&key, &nonce);

    chacha20_poly1305.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &[
        0x64, 0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4, 
        0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd,
        0x5e, 0x80, 0x5c, 0xfd, 0x34, 0x5c, 0xf3, 0x89, 
        0xf1, 0x08, 0x67, 0x0a, 0xc7, 0x6c, 0x8c, 0xb2,
        0x4c, 0x6c, 0xfc, 0x18, 0x75, 0x5d, 0x43, 0xee, 
        0xa0, 0x9e, 0xe9, 0x4e, 0x38, 0x2d, 0x26, 0xb0,
        0xbd, 0xb7, 0xb7, 0x3c, 0x32, 0x1b, 0x01, 0x00, 
        0xd4, 0xf0, 0x3b, 0x7f, 0x35, 0x58, 0x94, 0xcf,
        0x33, 0x2f, 0x83, 0x0e, 0x71, 0x0b, 0x97, 0xce, 
        0x98, 0xc8, 0xa8, 0x4a, 0xbd, 0x0b, 0x94, 0x81,
        0x14, 0xad, 0x17, 0x6e, 0x00, 0x8d, 0x33, 0xbd, 
        0x60, 0xf9, 0x82, 0xb1, 0xff, 0x37, 0xc8, 0x55,
        0x97, 0x97, 0xa0, 0x6e, 0xf4, 0xf0, 0xef, 0x61, 
        0xc1, 0x86, 0x32, 0x4e, 0x2b, 0x35, 0x06, 0x38,
        0x36, 0x06, 0x90, 0x7b, 0x6a, 0x7c, 0x02, 0xb0, 
        0xf9, 0xf6, 0x15, 0x7b, 0x53, 0xc8, 0x67, 0xe4,
        0xb9, 0x16, 0x6c, 0x76, 0x7b, 0x80, 0x4d, 0x46, 
        0xa5, 0x9b, 0x52, 0x16, 0xcd, 0xe7, 0xa4, 0xe9,
        0x90, 0x40, 0xc5, 0xa4, 0x04, 0x33, 0x22, 0x5e, 
        0xe2, 0x82, 0xa1, 0xb0, 0xa0, 0x6c, 0x52, 0x3e,
        0xaf, 0x45, 0x34, 0xd7, 0xf8, 0x3f, 0xa1, 0x15, 
        0x5b, 0x00, 0x47, 0x71, 0x8c, 0xbc, 0x54, 0x6a,
        0x0d, 0x07, 0x2b, 0x04, 0xb3, 0x56, 0x4e, 0xea, 
        0x1b, 0x42, 0x22, 0x73, 0xf5, 0x48, 0x27, 0x1a,
        0x0b, 0xb2, 0x31, 0x60, 0x53, 0xfa, 0x76, 0x99, 
        0x19, 0x55, 0xeb, 0xd6, 0x31, 0x59, 0x43, 0x4e,
        0xce, 0xbb, 0x4e, 0x46, 0x6d, 0xae, 0x5a, 0x10, 
        0x73, 0xa6, 0x72, 0x76, 0x27, 0x09, 0x7a, 0x10,
        0x49, 0xe6, 0x17, 0xd9, 0x1d, 0x36, 0x10, 0x94, 
        0xfa, 0x68, 0xf0, 0xff, 0x77, 0x98, 0x71, 0x30,
        0x30, 0x5b, 0xea, 0xba, 0x2e, 0xda, 0x04, 0xdf, 
        0x99, 0x7b, 0x71, 0x4d, 0x6c, 0x6f, 0x2c, 0x29,
        0xa6, 0xad, 0x5c, 0xb4, 0x02, 0x2b, 0x02, 0x70, 
        0x9b,
        0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22, 
        0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f, 0x38,
    ][..]);

    let mut chacha20_poly1305 = Chacha20Poly1305::new(&key, &nonce);
    
    let ret = chacha20_poly1305.aead_decrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(ret, true);

    let cleartext = &ciphertext_and_tag[..plen];
    assert_eq!(&plaintext[..], &cleartext[..]);
}

// Appendix A.  Additional Test Vectors
// https://tools.ietf.org/html/rfc8439#appendix-A