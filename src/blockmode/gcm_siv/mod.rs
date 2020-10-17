// AES-GCM-SIV: Specification and Analysis
// https://eprint.iacr.org/2017/168.pdf
// 
// AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption
// https://tools.ietf.org/html/rfc8452
use crate::aes::Aes128;

use subtle;


// AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption
// https://tools.ietf.org/html/rfc8452
// 
// AEAD_AES_128_GCM_SIV
// AEAD_AES_256_GCM_SIV

// Carry-less Multiplication
#[inline]
fn cl_mul(a: u64, b: u64, dst: &mut [u64; 2]) {
    dst[0] = 0;
    dst[1] = 0;

    for i in 0u64..64 {
        if (b & (1u64 << i)) != 0 {
            dst[1] ^= a;
        }

        // Shift the result
        dst[0] >>= 1;

        if (dst[1] & (1u64 << 0)) != 0 {
            dst[0] ^= 1u64 << 63;
        }

        dst[1] >>= 1;
    }
}

#[derive(Debug, Clone)]
pub struct Polyval {
    key: [u8; 16],
    h: [u8; 16],
}

impl Polyval {
    pub const KEY_LEN: usize    = 16;
    pub const OUTPUT_LEN: usize = 16;

    pub fn new(k: &[u8]) -> Self {
        assert_eq!(k.len(), Self::KEY_LEN);

        let h = [0u8; Self::OUTPUT_LEN];

        let mut key = [0u8; Self::KEY_LEN];
        key.copy_from_slice(&k[..Self::KEY_LEN]);

        Self { key, h  }
    }

    #[inline]
    pub fn reset(&mut self) {
        self.h = [0u8; 16];
    }

    fn gf_mul(&mut self) {
        // a: h
        // b: key
        let a = [
            u64::from_le_bytes([
                self.h[0], self.h[1], self.h[2], self.h[3],
                self.h[4], self.h[5], self.h[6], self.h[7],
            ]),
            u64::from_le_bytes([
                self.h[ 8], self.h[ 9], self.h[10], self.h[11],
                self.h[12], self.h[13], self.h[14], self.h[15],
            ]),
        ];

        let b = [
            u64::from_le_bytes([
                self.key[0], self.key[1], self.key[2], self.key[3],
                self.key[4], self.key[5], self.key[6], self.key[7],
            ]),
            u64::from_le_bytes([
                self.key[ 8], self.key[ 9], self.key[10], self.key[11],
                self.key[12], self.key[13], self.key[14], self.key[15],
            ]),
        ];

        let mut tmp1 = [0u64; 2];
        let mut tmp2 = [0u64; 2];
        let mut tmp3 = [0u64; 2];
        let mut tmp4 = [0u64; 2];

        cl_mul(a[0], b[0], &mut tmp1); // 0x00
        cl_mul(a[1], b[0], &mut tmp2); // 0x01
        cl_mul(a[0], b[1], &mut tmp3); // 0x10
        cl_mul(a[1], b[1], &mut tmp4); // 0x11

        tmp2[0] ^= tmp3[0];
        tmp2[1] ^= tmp3[1];

        tmp3[0] = 0;
        tmp3[1] = tmp2[0];
        
        tmp2[0] = tmp2[1];
        tmp2[1] = 0;
        
        tmp1[0] ^= tmp3[0];
        tmp1[1] ^= tmp3[1];
        
        tmp4[0] ^= tmp2[0];
        tmp4[1] ^= tmp2[1];
        
        const XMMMASK: [u64; 2] = [0x1u64, 0xc200000000000000];

        cl_mul(XMMMASK[1], tmp1[0], &mut tmp2); // 0x01

        unsafe {
            let tmp33: &mut [u32; 4] = std::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp3);
            let tmp11: &mut [u32; 4] = std::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp1);

            tmp33[0] = tmp11[2];
            tmp33[1] = tmp11[3];
            tmp33[2] = tmp11[0];
            tmp33[3] = tmp11[1];
        }
        
        tmp1[0] = tmp2[0] ^ tmp3[0];
        tmp1[1] = tmp2[1] ^ tmp3[1];

        cl_mul(XMMMASK[1], tmp1[0], &mut tmp2); // 0x01

        unsafe {
            let tmp33: &mut [u32; 4] = std::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp3);
            let tmp11: &mut [u32; 4] = std::mem::transmute::<&mut [u64; 2], &mut [u32; 4]>(&mut tmp1);

            tmp33[0] = tmp11[2];
            tmp33[1] = tmp11[3];
            tmp33[2] = tmp11[0];
            tmp33[3] = tmp11[1];
        }

        tmp1[0] = tmp2[0] ^ tmp3[0];
        tmp1[1] = tmp2[1] ^ tmp3[1];
        
        tmp4[0] ^= tmp1[0];
        tmp4[1] ^= tmp1[1];

        self.h[0.. 8].copy_from_slice(&tmp4[0].to_le_bytes());
        self.h[8..16].copy_from_slice(&tmp4[1].to_le_bytes());
    }

    pub fn polyval(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            for i in 0..chunk.len() {
                self.h[i] ^= chunk[i];
            }
            self.gf_mul();
        }
    }
}

fn incr(block: &mut [u8]) {
    debug_assert_eq!(block.len(), 16);

    let counter = u32::from_le_bytes([block[0], block[1], block[2], block[3]]).wrapping_add(1).to_le_bytes();
    block[0] = counter[0];
    block[1] = counter[1];
    block[2] = counter[2];
    block[3] = counter[3];
}

// AEAD_AES_128_GCM_SIV
// P_MAX is 2^36, 
// A_MAX is 2^36, 
// N_MIN and N_MAX are 12, 
// C_MAX is 2^36 + 16

// AEAD_AES_256_GCM_SIV
// K_LEN is 32, 
// P_MAX is 2^36, 
// A_MAX is 2^36, 
// N_MIN and N_MAX are 12,
// C_MAX is 2^36 + 16


// AEAD_AES_128_GCM_SIV
#[derive(Debug, Clone)]
pub struct Aes128GcmSiv {
    cipher: Aes128,
    nonce: [u8; Self::NONCE_LEN],
    polyval: Polyval,
}

impl Aes128GcmSiv {
    pub const KEY_LEN: usize   = Aes128::KEY_LEN;
    pub const BLOCK_LEN: usize = Aes128::BLOCK_LEN;
    pub const TAG_LEN: usize   = 16;
    pub const NONCE_LEN: usize = 12;

    pub const P_MAX: usize = 68719476736;                 // 2^36
    pub const A_MAX: usize = 68719476736;                 // 2^36
    pub const C_MAX: usize = 68719476736 + Self::TAG_LEN; // 2^36 + 16

    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        assert_eq!(nonce.len(), Self::NONCE_LEN); // 96-Bits
        assert_eq!(Self::BLOCK_LEN, 16);
        // NOTE: GCM-SIV 并不支持和 AES192 算法进行搭配。
        assert!(Self::KEY_LEN == 16 || Self::KEY_LEN == 32);

        let cipher = Aes128::new(key);
        
        let mut counter_block = [0u8; Self::BLOCK_LEN];
        counter_block[4..16].copy_from_slice(nonce);

        // message_authentication_key
        let mut ak = [0u8; Self::BLOCK_LEN];
        // message_encryption_key
        let mut ek = [0u8; Self::KEY_LEN];

        let mut tmp = counter_block.clone();
        tmp[0] = 0;
        cipher.encrypt(&mut tmp);
        ak[0..8].copy_from_slice(&tmp[0..8]);

        tmp = counter_block.clone();
        tmp[0] = 1;
        cipher.encrypt(&mut tmp);
        ak[8..16].copy_from_slice(&tmp[0..8]);

        tmp = counter_block.clone();
        tmp[0] = 2;
        cipher.encrypt(&mut tmp);
        ek[0..8].copy_from_slice(&tmp[0..8]);

        tmp = counter_block.clone();
        tmp[0] = 3;
        cipher.encrypt(&mut tmp);
        ek[8..16].copy_from_slice(&tmp[0..8]);

        // AES-256
        if Self::KEY_LEN == 32 {
            tmp = counter_block.clone();
            tmp[0] = 4;
            cipher.encrypt(&mut tmp);
            ek[16..24].copy_from_slice(&tmp[0..8]);

            tmp = counter_block.clone();
            tmp[0] = 5;
            cipher.encrypt(&mut tmp);
            ek[24..32].copy_from_slice(&tmp[0..8]);
        }

        let cipher = Aes128::new(&ek);

        let mut n = [0u8; Self::NONCE_LEN];
        n.copy_from_slice(&nonce[..Self::NONCE_LEN]);
        let nonce = n;

        let polyval = Polyval::new(&ak);

        Self { cipher, nonce, polyval }
    }
    
    #[inline]
    pub fn ae_encrypt(&mut self, plaintext_and_ciphertext: &mut [u8]) {
        self.aead_encrypt(&[], plaintext_and_ciphertext);
    }
    
    #[inline]
    pub fn ae_decrypt(&mut self, ciphertext_and_plaintext: &mut [u8]) -> bool {
        self.aead_decrypt(&[], ciphertext_and_plaintext)
    }
    
    pub fn aead_encrypt(&mut self, aad: &[u8], plaintext_and_ciphertext: &mut [u8]) {
        // 4.  Encryption
        // https://tools.ietf.org/html/rfc8452#section-4
        debug_assert!(aad.len() < Self::A_MAX);
        debug_assert!(plaintext_and_ciphertext.len() < Self::C_MAX);
        debug_assert!(plaintext_and_ciphertext.len() >= Self::TAG_LEN);

        let alen = aad.len();
        let plen = plaintext_and_ciphertext.len() - Self::TAG_LEN;

        let plaintext = &plaintext_and_ciphertext[..plen];

        let mut bit_len_block = [0u8; Self::BLOCK_LEN];
        let aad_bit_len_octets = (alen as u64 * 8).to_le_bytes();
        let plaintext_bit_len_octets = (plen as u64 * 8).to_le_bytes();
        bit_len_block[0.. 8].copy_from_slice(&aad_bit_len_octets);
        bit_len_block[8..16].copy_from_slice(&plaintext_bit_len_octets);

        self.polyval.reset();

        self.polyval.polyval(aad);
        self.polyval.polyval(plaintext);
        self.polyval.polyval(&bit_len_block);

        for i in 0..Self::NONCE_LEN {
            self.polyval.h[i] ^= self.nonce[i];
        }

        self.polyval.h[15] &= 0x7f;

        // tag = AES(key = message_encryption_key, block = S_s)
        let mut tag = self.polyval.h.clone();
        self.cipher.encrypt(&mut tag);

        // u32 (Counter) || u96 (Nonce)
        let mut counter_block = tag.clone();
        counter_block[15] |= 0x80;

        // CTR
        let plaintext = &mut plaintext_and_ciphertext[..plen];
        for chunk in plaintext.chunks_mut(Self::BLOCK_LEN) {
            let mut keystream_block = counter_block.clone();
            self.cipher.encrypt(&mut keystream_block);

            incr(&mut counter_block);
            
            for i in 0..chunk.len() {
                chunk[i] ^= keystream_block[i];
            }
        }

        // Save TAG
        &mut plaintext_and_ciphertext[plen..plen + Self::TAG_LEN].copy_from_slice(&tag);
    }

    pub fn aead_decrypt(&mut self, aad: &[u8], ciphertext_and_plaintext: &mut [u8]) -> bool {
        debug_assert!(aad.len() < Self::A_MAX);
        debug_assert!(ciphertext_and_plaintext.len() < Self::C_MAX);
        debug_assert!(ciphertext_and_plaintext.len() >= Self::TAG_LEN);
        
        let alen = aad.len();
        let clen = ciphertext_and_plaintext.len() - Self::TAG_LEN;
        
        // Input TAG
        let input_tag = &ciphertext_and_plaintext[clen..clen + Self::TAG_LEN];

        let mut counter_block = [0u8; Self::BLOCK_LEN];
        counter_block.copy_from_slice(&input_tag);
        counter_block[15] |= 0x80;
        
        // CTR
        let ciphertext = &mut ciphertext_and_plaintext[..clen];
        for chunk in ciphertext.chunks_mut(Self::BLOCK_LEN) {
            let mut keystream_block = counter_block.clone();
            self.cipher.encrypt(&mut keystream_block);

            incr(&mut counter_block);

            for i in 0..chunk.len() {
                chunk[i] ^= keystream_block[i];
            }
        }

        let cleartext = &ciphertext_and_plaintext[..clen];
        // Auth
        let mut bit_len_block = [0u8; Self::BLOCK_LEN];
        let aad_bit_len_octets = (alen as u64 * 8).to_le_bytes();
        let ciphertext_bit_len_octets = (clen as u64 * 8).to_le_bytes();
        bit_len_block[0.. 8].copy_from_slice(&aad_bit_len_octets);
        bit_len_block[8..16].copy_from_slice(&ciphertext_bit_len_octets);

        self.polyval.reset();

        self.polyval.polyval(aad);
        self.polyval.polyval(cleartext);
        self.polyval.polyval(&bit_len_block);

        for i in 0..Self::NONCE_LEN {
            self.polyval.h[i] ^= self.nonce[i];
        }
        self.polyval.h[15] &= 0x7f;

        // Expected TAG
        let mut tag = self.polyval.h.clone();
        self.cipher.encrypt(&mut tag);

        // Verify
        let input_tag = &ciphertext_and_plaintext[clen..clen + Self::TAG_LEN];
        // TODO: 使用 Result 类型抛出 `TagMisMatch` 错误？
        bool::from(subtle::ConstantTimeEq::ct_eq(input_tag, &tag))
    }
}



#[test]
fn test_aes128_gcm_siv_dec() {
    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("").unwrap();
    let mut ciphertext_and_tag = hex::decode("dc20e2d83f25705bb49e439eca56de25").unwrap();

    let plen      = plaintext.len();
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    let ret = cipher.aead_decrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(ret, true);
    assert_eq!(&ciphertext_and_tag[..plen], &plaintext[..]);


    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("01000000000000000000000000000000\
02000000000000000000000000000000\
03000000000000000000000000000000").unwrap();
    let mut ciphertext_and_tag = hex::decode("3fd24ce1f5a67b75bf2351f181a475c7\
b800a5b4d3dcf70106b1eea82fa1d64d\
f42bf7226122fa92e17a40eeaac1201b\
5e6e311dbf395d35b0fe39c2714388f8").unwrap();

    let plen      = plaintext.len();

    // let mut ciphertext_and_tag = plaintext.clone();
    // ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    let ret = cipher.aead_decrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(ret, true);
    assert_eq!(&ciphertext_and_tag[..plen], &plaintext[..]);
}

#[test]
fn test_aes128_gcm_siv() {
    // C.1.  AEAD_AES_128_GCM_SIV
    // https://tools.ietf.org/html/rfc8452#appendix-C.1
    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("dc20e2d83f25705bb49e439eca56de25").unwrap()[..]);

    
    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("0100000000000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("b5d839330ac7b786578782fff6013b81\
5b287c22493a364c").unwrap()[..]);

    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("010000000000000000000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("7323ea61d05932260047d942a4978db3\
57391a0bc4fdec8b0d106639").unwrap()[..]);

    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("01000000000000000000000000000000\
02000000000000000000000000000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("84e07e62ba83a6585417245d7ec413a9\
fe427d6315c09b57ce45f2e3936a9445\
1a8e45dcd4578c667cd86847bf6155ff").unwrap()[..]);

    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("01000000000000000000000000000000\
02000000000000000000000000000000\
03000000000000000000000000000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("3fd24ce1f5a67b75bf2351f181a475c7\
b800a5b4d3dcf70106b1eea82fa1d64d\
f42bf7226122fa92e17a40eeaac1201b\
5e6e311dbf395d35b0fe39c2714388f8").unwrap()[..]);

    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("01000000000000000000000000000000\
02000000000000000000000000000000\
03000000000000000000000000000000\
04000000000000000000000000000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("2433668f1058190f6d43e360f4f35cd8\
e475127cfca7028ea8ab5c20f7ab2af0\
2516a2bdcbc08d521be37ff28c152bba\
36697f25b4cd169c6590d1dd39566d3f\
8a263dd317aa88d56bdf3936dba75bb8").unwrap()[..]);

    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("01").unwrap();
    let plaintext = hex::decode("0200000000000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("1e6daba35669f4273b0a1a2560969cdf\
790d99759abd1508").unwrap()[..]);

    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("01").unwrap();
    let plaintext = hex::decode("020000000000000000000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("296c7889fd99f41917f4462008299c51\
02745aaa3a0c469fad9e075a").unwrap()[..]);

    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("01").unwrap();
    let plaintext = hex::decode("02000000000000000000000000000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("e2b0c5da79a901c1745f700525cb335b\
8f8936ec039e4e4bb97ebd8c4457441f").unwrap()[..]);


    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("01").unwrap();
    let plaintext = hex::decode("02000000000000000000000000000000\
03000000000000000000000000000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("620048ef3c1e73e57e02bb8562c416a3\
19e73e4caac8e96a1ecb2933145a1d71\
e6af6a7f87287da059a71684ed3498e1").unwrap()[..]);

    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("01").unwrap();
    let plaintext = hex::decode("02000000000000000000000000000000\
03000000000000000000000000000000\
04000000000000000000000000000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("50c8303ea93925d64090d07bd109dfd9\
515a5a33431019c17d93465999a8b005\
3201d723120a8562b838cdff25bf9d1e\
6a8cc3865f76897c2e4b245cf31c51f2").unwrap()[..]);

    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("01").unwrap();
    let plaintext = hex::decode("02000000000000000000000000000000\
03000000000000000000000000000000\
04000000000000000000000000000000\
05000000000000000000000000000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("2f5c64059db55ee0fb847ed513003746\
aca4e61c711b5de2e7a77ffd02da42fe\
ec601910d3467bb8b36ebbaebce5fba3\
0d36c95f48a3e7980f0e7ac299332a80\
cdc46ae475563de037001ef84ae21744").unwrap()[..]);


    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("010000000000000000000000").unwrap();
    let plaintext = hex::decode("02000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("a8fe3e8707eb1f84fb28f8cb73de8e99\
e2f48a14").unwrap()[..]);

    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("01000000000000000000000000000000\
0200").unwrap();
    let plaintext = hex::decode("03000000000000000000000000000000\
04000000").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("6bb0fecf5ded9b77f902c7d5da236a43\
91dd029724afc9805e976f451e6d87f6\
fe106514").unwrap()[..]);

    let key       = hex::decode("01000000000000000000000000000000").unwrap();
    let nonce     = hex::decode("030000000000000000000000").unwrap();
    let aad       = hex::decode("01000000000000000000000000000000\
02000000").unwrap();
    let plaintext = hex::decode("03000000000000000000000000000000\
0400").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("44d0aaf6fb2f1f34add5e8064e83e12a\
2adabff9b2ef00fb47920cc72a0c0f13\
b9fd").unwrap()[..]);

    // ###########  New Key ###########
    let key       = hex::decode("e66021d5eb8e4f4066d4adb9c33560e4").unwrap();
    let nonce     = hex::decode("f46e44bb3da0015c94f70887").unwrap();
    let aad       = hex::decode("").unwrap();
    let plaintext = hex::decode("").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("a4194b79071b01a87d65f706e3949578").unwrap()[..]);

    let key       = hex::decode("36864200e0eaf5284d884a0e77d31646").unwrap();
    let nonce     = hex::decode("bae8e37fc83441b16034566b").unwrap();
    let aad       = hex::decode("46bb91c3c5").unwrap();
    let plaintext = hex::decode("7a806c").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("af60eb711bd85bc1e4d3e0a462e074ee\
a428a8").unwrap()[..]);

    // //////////////////////
    let key       = hex::decode("aedb64a6c590bc84d1a5e269e4b47801").unwrap();
    let nonce     = hex::decode("afc0577e34699b9e671fdd4f").unwrap();
    let aad       = hex::decode("fc880c94a95198874296").unwrap();
    let plaintext = hex::decode("bdc66f146545").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("bb93a3e34d3cd6a9c45545cfc11f03ad\
743dba20f966").unwrap()[..]);

    let key       = hex::decode("d5cc1fd161320b6920ce07787f86743b").unwrap();
    let nonce     = hex::decode("275d1ab32f6d1f0434d8848c").unwrap();
    let aad       = hex::decode("046787f3ea22c127aaf195d1894728").unwrap();
    let plaintext = hex::decode("1177441f195495860f").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("4f37281f7ad12949d01d02fd0cd174c8\
4fc5dae2f60f52fd2b").unwrap()[..]);

    let key       = hex::decode("b3fed1473c528b8426a582995929a149").unwrap();
    let nonce     = hex::decode("9e9ad8780c8d63d0ab4149c0").unwrap();
    let aad       = hex::decode("c9882e5386fd9f92ec489c8fde2be2cf\
97e74e93").unwrap();
    let plaintext = hex::decode("9f572c614b4745914474e7c7").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("f54673c5ddf710c745641c8bc1dc2f87\
1fb7561da1286e655e24b7b0").unwrap()[..]);

    let key       = hex::decode("2d4ed87da44102952ef94b02b805249b").unwrap();
    let nonce     = hex::decode("ac80e6f61455bfac8308a2d4").unwrap();
    let aad       = hex::decode("2950a70d5a1db2316fd568378da107b5\
2b0da55210cc1c1b0a").unwrap();
    let plaintext = hex::decode("0d8c8451178082355c9e940fea2f58").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("c9ff545e07b88a015f05b274540aa183\
b3449b9f39552de99dc214a1190b0b").unwrap()[..]);

    let key       = hex::decode("bde3b2f204d1e9f8b06bc47f9745b3d1").unwrap();
    let nonce     = hex::decode("ae06556fb6aa7890bebc18fe").unwrap();
    let aad       = hex::decode("1860f762ebfbd08284e421702de0de18\
baa9c9596291b08466f37de21c7f").unwrap();
    let plaintext = hex::decode("6b3db4da3d57aa94842b9803a96e07fb\
6de7").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("6298b296e24e8cc35dce0bed484b7f30\
d5803e377094f04709f64d7b985310a4\
db84").unwrap()[..]);

    let key       = hex::decode("f901cfe8a69615a93fdf7a98cad48179").unwrap();
    let nonce     = hex::decode("6245709fb18853f68d833640").unwrap();
    let aad       = hex::decode("7576f7028ec6eb5ea7e298342a94d4b2\
02b370ef9768ec6561c4fe6b7e7296fa\
859c21").unwrap();
    let plaintext = hex::decode("e42a3c02c25b64869e146d7b233987bd\
dfc240871d").unwrap();
    let plen      = plaintext.len();
    let alen      = aad.len();
    let mut ciphertext_and_tag = plaintext.clone();
    ciphertext_and_tag.resize(plen + Aes128GcmSiv::TAG_LEN, 0);
    let mut cipher = Aes128GcmSiv::new(&key, &nonce);
    cipher.aead_encrypt(&aad, &mut ciphertext_and_tag);
    assert_eq!(&ciphertext_and_tag[..], &hex::decode("391cc328d484a4f46406181bcd62efd9\
b3ee197d052d15506c84a9edd65e13e9\
d24a2a6e70").unwrap()[..]);
}




#[test]
fn test_aes256_gcm_siv() {
    // C.2.  AEAD_AES_256_GCM_SIV
    // https://tools.ietf.org/html/rfc8452#appendix-C.2

}