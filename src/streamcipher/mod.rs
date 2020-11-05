pub use crate::blockmode::{
    Sm4Ctr,
    Aes128Ctr, Aes192Ctr, Aes256Ctr,
    Aria128Ctr, Aria192Ctr, Aria256Ctr,
    Camellia128Ctr, Camellia192Ctr, Camellia256Ctr,

    Sm4Ofb,
    Aes128Ofb, Aes192Ofb, Aes256Ofb,
    Aria128Ofb, Aria192Ofb, Aria256Ofb,
    Camellia128Ofb, Camellia192Ofb, Camellia256Ofb,

    Sm4Cfb1,
    Aes128Cfb1, Aes192Cfb1, Aes256Cfb1,
    Aria128Cfb1, Aria192Cfb1, Aria256Cfb1,
    Camellia128Cfb1, Camellia192Cfb1, Camellia256Cfb1,

    Sm4Cfb8,
    Aes128Cfb8, Aes192Cfb8, Aes256Cfb8,
    Aria128Cfb8, Aria192Cfb8, Aria256Cfb8,
    Camellia128Cfb8, Camellia192Cfb8, Camellia256Cfb8,

    Sm4Cfb128,
    Aes128Cfb128, Aes192Cfb128, Aes256Cfb128,
    Aria128Cfb128, Aria192Cfb128, Aria256Cfb128,
    Camellia128Cfb128, Camellia192Cfb128, Camellia256Cfb128,
};


mod rc4;
mod chacha20;

pub use self::rc4::*;
pub use self::chacha20::*;


#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum StreamCipherKind {
    SM4_CTR,
    SM4_OFB,
    SM4_CFB1,
    SM4_CFB8,
    SM4_CFB128,

    AES128_CTR,
    AES192_CTR,
    AES256_CTR,
    
    AES128_OFB,
    AES192_OFB,
    AES256_OFB,
    
    AES128_CFB1,
    AES192_CFB1,
    AES256_CFB1,

    AES128_CFB8,
    AES192_CFB8,
    AES256_CFB8,

    AES128_CFB128,
    AES192_CFB128,
    AES256_CFB128,
    
    CAMELLIA128_CTR,
    CAMELLIA192_CTR,
    CAMELLIA256_CTR,

    CAMELLIA128_OFB,
    CAMELLIA192_OFB,
    CAMELLIA256_OFB,

    CAMELLIA128_CFB1,
    CAMELLIA192_CFB1,
    CAMELLIA256_CFB1,

    CAMELLIA128_CFB8,
    CAMELLIA192_CFB8,
    CAMELLIA256_CFB8,
    
    CAMELLIA128_CFB128,
    CAMELLIA192_CFB128,
    CAMELLIA256_CFB128,

    RC4,
    CHACHA20,
    ZUC,
    
    Private(&'static str),
}



// =============================  对称序列密码（流密码）  =============================
// pub trait StreamCipherEncrytor {
//     // 流密码 流式数据加密
//     fn update(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
//     fn finalize(self);
// }

// pub trait StreamCipherDecryptor {
//     // 流密码 流式数据解密
//     fn update(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);
//     fn finalize(self);
// }

pub trait StreamCipher: Sized {
    const KIND: StreamCipherKind;
    const KEY_LEN: usize;
    const BLOCK_LEN: usize;
    const NONCE_LEN: usize;
    
    // type Encryptor: StreamCipherEncrytor;
    // type Decryptor: StreamCipherDecryptor;

    fn new(key: &[u8], nonce: &[u8]) -> Self;

    fn encrypt_slice_oneshot(key: &[u8], nonce: &[u8], plaintext_in_and_ciphertext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.encrypt_slice(plaintext_in_and_ciphertext_out);
    }

    fn decrypt_slice_oneshot(key: &[u8], nonce: &[u8], ciphertext_in_and_plaintext_out: &mut [u8]) {
        let mut cipher = Self::new(key, nonce);
        cipher.decrypt_slice(ciphertext_in_and_plaintext_out);
    }

    fn encrypt_slice(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]);
    fn decrypt_slice(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]);

    // fn encrypt_stream(&self) -> Self::Encryptor;
    // fn decrypt_stream(&self) -> Self::Encryptor;
}

macro_rules! impl_stream_cipher {
    ($name:tt, $kind:tt) => {
        impl StreamCipher for $name {
            const KIND: StreamCipherKind = StreamCipherKind::$kind;
            const KEY_LEN: usize   = $name::KEY_LEN;
            const BLOCK_LEN: usize = $name::BLOCK_LEN;
            const NONCE_LEN: usize = $name::NONCE_LEN;
            
            fn new(key: &[u8], nonce: &[u8]) -> Self {
                Self::new(key, nonce)
            }

            fn encrypt_slice(&mut self, plaintext_in_and_ciphertext_out: &mut [u8]) {
                self.encrypt(plaintext_in_and_ciphertext_out);
            }

            fn decrypt_slice(&mut self, ciphertext_in_and_plaintext_out: &mut [u8]) {
                self.decrypt(ciphertext_in_and_plaintext_out);
            }
        }
    }
}




// // SM4
// impl_stream_cipher!(Sm4Ctr, SM4_CTR);
// impl_stream_cipher!(Sm4Ofb, SM4_OFB);
// impl_stream_cipher!(Sm4Cfb1, SM4_CFB1);
// impl_stream_cipher!(Sm4Cfb8, SM4_CFB8);
// impl_stream_cipher!(Sm4Cfb128, SM4_CFB128);

// // AES
// impl_stream_cipher!(Aes128Ctr, AES128_CTR);
// impl_stream_cipher!(Aes128Ofb, AES128_OFB);
// impl_stream_cipher!(Aes128Cfb1, AES128_CFB1);
// impl_stream_cipher!(Aes128Cfb8, AES128_CFB8);
// impl_stream_cipher!(Aes128Cfb128, AES128_CFB128);

// impl_stream_cipher!(Aes192Ctr, AES192_CTR);
// impl_stream_cipher!(Aes192Ofb, AES192_OFB);
// impl_stream_cipher!(Aes192Cfb1, AES192_CFB1);
// impl_stream_cipher!(Aes192Cfb8, AES192_CFB8);
// impl_stream_cipher!(Aes192Cfb128, AES192_CFB128);

// impl_stream_cipher!(Aes256Ctr, AES256_CTR);
// impl_stream_cipher!(Aes256Ofb, AES256_OFB);
// impl_stream_cipher!(Aes256Cfb1, AES256_CFB1);
// impl_stream_cipher!(Aes256Cfb8, AES256_CFB8);
// impl_stream_cipher!(Aes256Cfb128, AES256_CFB128);

// // Camellia
// impl_stream_cipher!(Camellia128Ctr, CAMELLIA128_CTR);
// impl_stream_cipher!(Camellia128Ofb, CAMELLIA128_OFB);
// impl_stream_cipher!(Camellia128Cfb1, CAMELLIA128_CFB1);
// impl_stream_cipher!(Camellia128Cfb8, CAMELLIA128_CFB8);
// impl_stream_cipher!(Camellia128Cfb128, CAMELLIA128_CFB128);

// impl_stream_cipher!(Camellia192Ctr, CAMELLIA192_CTR);
// impl_stream_cipher!(Camellia192Ofb, CAMELLIA192_OFB);
// impl_stream_cipher!(Camellia192Cfb1, CAMELLIA192_CFB1);
// impl_stream_cipher!(Camellia192Cfb8, CAMELLIA192_CFB8);
// impl_stream_cipher!(Camellia192Cfb128, CAMELLIA192_CFB128);

// impl_stream_cipher!(Camellia256Ctr, CAMELLIA256_CTR);
// impl_stream_cipher!(Camellia256Ofb, CAMELLIA256_OFB);
// impl_stream_cipher!(Camellia256Cfb1, CAMELLIA256_CFB1);
// impl_stream_cipher!(Camellia256Cfb8, CAMELLIA256_CFB8);
// impl_stream_cipher!(Camellia256Cfb128, CAMELLIA256_CFB128);

// // Chacha20
// impl_stream_cipher!(Chacha20, CHACHA20);



#[cfg(test)]
#[bench]
fn bench_rc4(b: &mut test::Bencher) {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let mut ciphertext = test::black_box([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    
    let mut cipher = Rc4::new(&key);
    
    b.bytes = 16;
    b.iter(|| {
        cipher.encrypt_slice(&mut ciphertext);
    })
}

#[cfg(test)]
#[bench]
fn bench_chacha20(b: &mut test::Bencher) {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00
    ];

    let mut plaintext_and_ciphertext = test::black_box([1u8; Chacha20::BLOCK_LEN]);
    
    let chacha20 = Chacha20::new(&key);
    
    b.bytes = Chacha20::BLOCK_LEN as u64;
    b.iter(|| {
        chacha20.encrypt_slice(1, &nonce, &mut plaintext_and_ciphertext);
    })
}

