// Authenticated Encryption with Associated Data (AEAD) Parameters
// https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
// 
// Last Updated: 2019-04-18
// 
// Numeric ID   Name                        Reference
// 1            AEAD_AES_128_GCM            [RFC5116]
// 2            AEAD_AES_256_GCM            [RFC5116]
// 3            AEAD_AES_128_CCM            [RFC5116]
// 4            AEAD_AES_256_CCM            [RFC5116]
// 5            AEAD_AES_128_GCM_8          [RFC5282]
// 6            AEAD_AES_256_GCM_8          [RFC5282]
// 7            AEAD_AES_128_GCM_12         [RFC5282]
// 8            AEAD_AES_256_GCM_12         [RFC5282]
// 9            AEAD_AES_128_CCM_SHORT      [RFC5282]
// 10           AEAD_AES_256_CCM_SHORT      [RFC5282]
// 11           AEAD_AES_128_CCM_SHORT_8    [RFC5282]
// 12           AEAD_AES_256_CCM_SHORT_8    [RFC5282]
// 13           AEAD_AES_128_CCM_SHORT_12   [RFC5282]
// 14           AEAD_AES_256_CCM_SHORT_12   [RFC5282]
// 15           AEAD_AES_SIV_CMAC_256       [RFC5297]
// 16           AEAD_AES_SIV_CMAC_384       [RFC5297]
// 17           AEAD_AES_SIV_CMAC_512       [RFC5297]
// 18           AEAD_AES_128_CCM_8          [RFC6655]
// 19           AEAD_AES_256_CCM_8          [RFC6655]
// 20           AEAD_AES_128_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 21           AEAD_AES_128_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 22           AEAD_AES_128_OCB_TAGLEN64   [RFC7253, Section 3.1]
// 23           AEAD_AES_192_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 24           AEAD_AES_192_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 25           AEAD_AES_192_OCB_TAGLEN64   [RFC7253, Section 3.1]
// 26           AEAD_AES_256_OCB_TAGLEN128  [RFC7253, Section 3.1]
// 27           AEAD_AES_256_OCB_TAGLEN96   [RFC7253, Section 3.1]
// 28           AEAD_AES_256_OCB_TAGLEN64   [RFC7253, Section 3.1]
// 29           AEAD_CHACHA20_POLY1305      [RFC8439]
// 30           AEAD_AES_128_GCM_SIV        [RFC8452]
// 31           AEAD_AES_256_GCM_SIV        [RFC8452]
// 32-32767     Unassigned
// 32768-65535  Reserved for Private Use    [RFC5116]
pub use crate::blockmode::{
    Aes128Gcm, Aes128Gcm8, Aes128Gcm12,
    Aes256Gcm, Aes256Gcm8, Aes256Gcm12,

    Aes128GcmSiv, Aes256GcmSiv,

    Aes128Ccm, Aes128CcmShort, Aes128CcmShort8, Aes128CcmShort12, Aes128Ccm8,
    Aes256Ccm, Aes256CcmShort, Aes256CcmShort8, Aes256CcmShort12, Aes256Ccm8,

    Aes128OcbTag64, Aes128OcbTag96, Aes128OcbTag128,
    Aes192OcbTag64, Aes192OcbTag96, Aes192OcbTag128,
    Aes256OcbTag64, Aes256OcbTag96, Aes256OcbTag128,

    AesSivCmac256, AesSivCmac384, AesSivCmac512,
    
    Aria128Ccm, Aria256Ccm, 
    Aria128Gcm, Aria256Gcm, 
    Aria128GcmSiv, Aria256GcmSiv, 
};


mod chacha20_poly1305;
pub use self::chacha20_poly1305::Chacha20Poly1305;


#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AeadCipherKind {
    AEAD_AES_128_GCM,
    AEAD_AES_256_GCM,
    AEAD_AES_128_CCM,
    AEAD_AES_256_CCM,
    AEAD_AES_128_GCM_8,
    AEAD_AES_256_GCM_8,
    AEAD_AES_128_GCM_12,
    AEAD_AES_256_GCM_12,
    AEAD_AES_128_CCM_SHORT,
    AEAD_AES_256_CCM_SHORT,
    AEAD_AES_128_CCM_SHORT_8,
    AEAD_AES_256_CCM_SHORT_8,
    AEAD_AES_128_CCM_SHORT_12,
    AEAD_AES_256_CCM_SHORT_12,
    AEAD_AES_SIV_CMAC_256,
    AEAD_AES_SIV_CMAC_384,
    AEAD_AES_SIV_CMAC_512,
    AEAD_AES_128_CCM_8,
    AEAD_AES_256_CCM_8,
    AEAD_AES_128_OCB_TAGLEN128,
    AEAD_AES_128_OCB_TAGLEN96,
    AEAD_AES_128_OCB_TAGLEN64,
    AEAD_AES_192_OCB_TAGLEN128,
    AEAD_AES_192_OCB_TAGLEN96,
    AEAD_AES_192_OCB_TAGLEN64,
    AEAD_AES_256_OCB_TAGLEN128,
    AEAD_AES_256_OCB_TAGLEN96,
    AEAD_AES_256_OCB_TAGLEN64,
    AEAD_CHACHA20_POLY1305,
    AEAD_AES_128_GCM_SIV,
    AEAD_AES_256_GCM_SIV,

    Private {
        id: u16,
        name: &'static str,
    },
}


pub trait AeadCipher: Sized {
    const KEY_LEN: usize;
    const BLOCK_LEN: usize;
    const TAG_LEN: usize;
    
    const P_MAX: usize;
    const C_MAX: usize;
    const N_MIN: usize;
    const N_MAX: usize;

    const AEAD_KIND: AeadCipherKind;
    // const AEAD_ID: u16;                 // IANA AEAD ID
    // const AEAD_NAME: &'static str;      // IANA AEAD Name
    // const AEAD_REFERENCE: &'static str; // IANA AEAD Reference

    // type AeadEncryptor: AeadStreamCipherEncrytor;
    // type AeadDecryptor: AeadStreamCipherDecryptor;

    // fn new(key: &[u8], nonce: &[u8]) -> Self;
    
    fn ae_encrypt_slice(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]) {
        self.aead_encrypt_slice(&[], plaintext_in_and_ciphertext_out)
    }
    fn ae_decrypt_slice(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]) -> bool {
        self.aead_decrypt_slice(&[], ciphertext_in_and_plaintext_out)
    }

    fn aead_encrypt_slice(&mut self, aad: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]);
    fn aead_decrypt_slice(&mut self, aad: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) -> bool;

    fn aead_encrypt_slice_detached(&mut self, aad: &[u8], plaintext_and_ciphertext: &mut [u8], tag_out: &mut [u8]);
    fn aead_decrypt_slice_detached(&mut self, aad: &[u8], ciphertext_and_plaintext: &mut [u8], tag_in: &[u8]) -> bool;

    // fn aead_encrypt_stream(&self) -> Self::AeadEncryptor;
    // fn aead_decrypt_stream(&self) -> Self::AeadDecryptor;
}


macro_rules! impl_aead_cipher {
    ($name:tt, $kind:tt) => {
        impl AeadCipher for $name {
            const KEY_LEN: usize   = $name::KEY_LEN;
            const BLOCK_LEN: usize = $name::BLOCK_LEN;
            const TAG_LEN: usize   = $name::TAG_LEN;
        
            const P_MAX: usize = $name::P_MAX;
            const C_MAX: usize = $name::C_MAX;

            const N_MIN: usize = $name::N_MIN;
            const N_MAX: usize = $name::N_MAX;

            const AEAD_KIND: AeadCipherKind = AeadCipherKind::$kind;
            // const AEAD_ID: u16                 = $aead_id;

            // fn new(key: &[u8], nonce: &[u8]) -> Self {
            //     Self::new(key, nonce)
            // }
            fn aead_encrypt_slice(&mut self, aad: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
                self.encrypt_slice(aad, plaintext_in_and_ciphertext_out)
            }

            fn aead_decrypt_slice(&mut self, aad: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) -> bool {
                self.decrypt_slice(aad, ciphertext_in_and_plaintext_out)
            }

            fn aead_encrypt_slice_detached(&mut self, aad: &[u8], plaintext_and_ciphertext: &mut [u8], tag_out: &mut [u8]) {
                self.encrypt_slice_detached(aad, plaintext_and_ciphertext, tag_out)
            }
            fn aead_decrypt_slice_detached(&mut self, aad: &[u8], ciphertext_and_plaintext: &mut [u8], tag_in: &[u8]) -> bool {
                self.decrypt_slice_detached(aad, ciphertext_and_plaintext, tag_in)
            }
        }
    }
}

macro_rules! impl_aead_cipher_with_siv_cmac {
    ($name:tt, $kind:tt) => {
        impl AeadCipher for $name {
            const KEY_LEN: usize   = $name::KEY_LEN;
            const BLOCK_LEN: usize = $name::BLOCK_LEN;
            const TAG_LEN: usize   = $name::TAG_LEN;
        
            const P_MAX: usize = $name::P_MAX;
            const C_MAX: usize = $name::C_MAX;

            const N_MIN: usize = $name::N_MIN;
            const N_MAX: usize = $name::N_MAX;

            const AEAD_KIND: AeadCipherKind = AeadCipherKind::$kind;
            // const AEAD_ID: u16                 = $aead_id;

            // fn new(key: &[u8], nonce: &[u8]) -> Self {
            //     Self::new(key, nonce)
            // }

            fn aead_encrypt_slice(&mut self, aad: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
                if aad.is_empty() { 
                    self.encrypt_slice(&[], plaintext_in_and_ciphertext_out)
                } else {
                    self.encrypt_slice(&[aad], plaintext_in_and_ciphertext_out)
                }
            }

            fn aead_decrypt_slice(&mut self, aad: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) -> bool {
                if aad.is_empty() {
                    self.decrypt_slice(&[], ciphertext_in_and_plaintext_out)
                } else {
                    self.decrypt_slice(&[aad], ciphertext_in_and_plaintext_out)
                }
            }

            fn aead_encrypt_slice_detached(&mut self, aad: &[u8], plaintext_and_ciphertext: &mut [u8], tag_out: &mut [u8]) {
                if aad.is_empty() { 
                    self.encrypt_slice_detached(&[], plaintext_and_ciphertext, tag_out)
                } else {
                    self.encrypt_slice_detached(&[aad], plaintext_and_ciphertext, tag_out)
                }
            }
            fn aead_decrypt_slice_detached(&mut self, aad: &[u8], ciphertext_and_plaintext: &mut [u8], tag_in: &[u8]) -> bool {
                if aad.is_empty() {
                    self.decrypt_slice_detached(&[], ciphertext_and_plaintext, tag_in)
                } else {
                    self.decrypt_slice_detached(&[aad], ciphertext_and_plaintext, tag_in)
                }
            }
        }
    }
}


// AES-GCM
// impl_aead_cipher!(Aes128Gcm,   AEAD_AES_128_GCM);
// impl_aead_cipher!(Aes128Gcm8,  AEAD_AES_128_GCM_8);
// impl_aead_cipher!(Aes128Gcm12, AEAD_AES_128_GCM_12);
// impl_aead_cipher!(Aes256Gcm,   AEAD_AES_256_GCM);
// impl_aead_cipher!(Aes256Gcm8,  AEAD_AES_256_GCM_8);
// impl_aead_cipher!(Aes256Gcm12, AEAD_AES_256_GCM_12);

// AES-GCM-SIV
// impl_aead_cipher!(Aes128GcmSiv, AEAD_AES_128_GCM_SIV);
// impl_aead_cipher!(Aes256GcmSiv, AEAD_AES_256_GCM_SIV);

// AES-CCM
// impl_aead_cipher!(Aes128Ccm,        AEAD_AES_128_CCM);
// impl_aead_cipher!(Aes128CcmShort,   AEAD_AES_128_CCM_SHORT);
// impl_aead_cipher!(Aes128CcmShort8,  AEAD_AES_128_CCM_SHORT_8);
// impl_aead_cipher!(Aes128CcmShort12, AEAD_AES_128_CCM_SHORT_12);
// impl_aead_cipher!(Aes128Ccm8,       AEAD_AES_128_CCM_8);

// impl_aead_cipher!(Aes256Ccm,        AEAD_AES_256_CCM);
// impl_aead_cipher!(Aes256CcmShort,   AEAD_AES_256_CCM_SHORT);
// impl_aead_cipher!(Aes256CcmShort8,  AEAD_AES_256_CCM_SHORT_8);
// impl_aead_cipher!(Aes256CcmShort12, AEAD_AES_256_CCM_SHORT_12);
// impl_aead_cipher!(Aes256Ccm8,       AEAD_AES_256_CCM_8);

// AES-SIV-CMAC
// impl_aead_cipher_with_siv_cmac!(AesSivCmac256, AEAD_AES_SIV_CMAC_256);
// impl_aead_cipher_with_siv_cmac!(AesSivCmac384, AEAD_AES_SIV_CMAC_384);
// impl_aead_cipher_with_siv_cmac!(AesSivCmac512, AEAD_AES_SIV_CMAC_512);

// AES-OCB
// impl_aead_cipher!(Aes128OcbTag64,  AEAD_AES_128_OCB_TAGLEN64);
// impl_aead_cipher!(Aes128OcbTag96,  AEAD_AES_128_OCB_TAGLEN96);
// impl_aead_cipher!(Aes128OcbTag128, AEAD_AES_128_OCB_TAGLEN128);

// impl_aead_cipher!(Aes192OcbTag64,  AEAD_AES_192_OCB_TAGLEN64);
// impl_aead_cipher!(Aes192OcbTag96,  AEAD_AES_192_OCB_TAGLEN96);
// impl_aead_cipher!(Aes192OcbTag128, AEAD_AES_192_OCB_TAGLEN128);

// impl_aead_cipher!(Aes256OcbTag64,  AEAD_AES_256_OCB_TAGLEN64);
// impl_aead_cipher!(Aes256OcbTag96,  AEAD_AES_256_OCB_TAGLEN96);
// impl_aead_cipher!(Aes256OcbTag128, AEAD_AES_256_OCB_TAGLEN128);

// Chacha20Poly1305
// impl_aead_cipher!(Chacha20Poly1305,  AEAD_CHACHA20_POLY1305);


#[cfg(test)]
#[bench]
fn bench_chacha20_poly1305_enc(b: &mut test::Bencher) {
    let key   = [1u8; Chacha20Poly1305::KEY_LEN];
    let nonce = [2u8; Chacha20Poly1305::NONCE_LEN];
    let aad   = [0u8; 0];
    
    let mut tag_out    = test::black_box([ 1u8; Chacha20Poly1305::TAG_LEN ]);
    let mut ciphertext = test::black_box([ 1u8; Chacha20Poly1305::BLOCK_LEN ]);
    
    let cipher = Chacha20Poly1305::new(&key);

    b.bytes = Chacha20Poly1305::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);
    })
}

#[cfg(test)]
#[bench]
fn bench_aes128_gcm_enc(b: &mut test::Bencher) {
    let key   = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = test::black_box([1u8; Aes128Gcm::BLOCK_LEN + Aes128Gcm::TAG_LEN]);
    let cipher = Aes128Gcm::new(&key);

    b.bytes = Aes128Gcm::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext);
    })
}
#[cfg(test)]
#[bench]
fn bench_aes128_gcm_siv_enc(b: &mut test::Bencher) {
    let key   = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = test::black_box([1u8; Aes128GcmSiv::BLOCK_LEN + Aes128GcmSiv::TAG_LEN]);
    let cipher = Aes128GcmSiv::new(&key);

    b.bytes = Aes128GcmSiv::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext);
    })
}
#[cfg(test)]
#[bench]
fn bench_aes128_ccm_enc(b: &mut test::Bencher) {
    let key   = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = test::black_box([1u8; Aes128Ccm::BLOCK_LEN + Aes128Ccm::TAG_LEN]);
    let cipher = Aes128Ccm::new(&key);

    b.bytes = Aes128Ccm::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext);
    })
}
#[cfg(test)]
#[bench]
fn bench_aes128_ocb_tag_128_enc(b: &mut test::Bencher) {
    let key   = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = test::black_box([1u8; Aes128OcbTag128::BLOCK_LEN + Aes128OcbTag128::TAG_LEN]);
    let cipher = Aes128OcbTag128::new(&key);

    b.bytes = Aes128OcbTag128::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(&nonce, &aad, &mut plaintext_and_ciphertext);
    })
}
#[cfg(test)]
#[bench]
fn bench_aes_siv_cmac_256_enc(b: &mut test::Bencher) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f\
000102030405060708090a0b0c0d0e0f").unwrap();
    let aad = [0u8; 0];

    let mut plaintext_and_ciphertext = test::black_box([1u8; AesSivCmac256::BLOCK_LEN + AesSivCmac256::TAG_LEN]);
    let cipher = AesSivCmac256::new(&key);

    b.bytes = AesSivCmac256::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(&[&aad], &mut plaintext_and_ciphertext);
    })
}