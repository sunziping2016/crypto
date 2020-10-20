// #![feature(const_generics, const_fn, const_generic_impls_guard)]
#![cfg_attr(test, feature(test))]
#![feature(stdsimd)]
#![allow(unused_macros, unused_variables, dead_code, unused_assignments, unused_imports)]

// #![no_std]

#[cfg(test)]
extern crate test;

extern crate subtle;
extern crate byteorder;

#[cfg(test)]
extern crate hex;

pub mod error;

// cryptographic hash function (CHF)
pub mod hash;
pub mod md2;
pub mod md4;
pub mod md5;
pub mod sha1;
pub mod sha2;
pub mod sha3; // TODO
pub mod sm3;

pub mod hmac;

// Key derivation function (KDF)
pub mod hkdf;
pub mod scrypt; // TODO

// pub mod cipher;

pub mod blockmode;
pub mod blockcipher;

pub mod streamcipher;

// AEAD Cipher
// pub mod aead;


// Elliptic Curve Cryptography（ECC）
// http://docs.rs/x25519-dalek
// http://docs.rs/ed25519-dalek

// RSA
// https://docs.rs/rsa

