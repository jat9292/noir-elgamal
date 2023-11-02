# noir-elgamal

A Noir library for Exponential ElGamal Encryption on the Baby Jubjub curve. 

To interact with it in a front-end or via Node JS install the accompanying npm package [babyjubjub-utils](https://www.npmjs.com/package/babyjubjub-utils). This is especially useful if you want to fully decrypt a ciphertext to its original integer format. 

Alternatively, you could also use the even faster accompanying Rust crate [babygiant-alt-bn128](https://crates.io/crates/babygiant-alt-bn128), but it is not usable directly in a front-end. The npm package converts the Rust code to WASM and uses Web Workers for increased efficiency under the hood.

# Installation

In your `Nargo.toml` file, add the following dependency:
```
[dependencies]
noir_elgamal = { tag = "v0.2.0", git = "https://github.com/jat9292/noir-elgamal" }
```

## Available Noir functions

### is_valid_subgroup
```rust
/// This function checks that a point is in the big prime subgroup of the Baby Jubjub curve. 
/// It is used to check that a public key is valid.
pub fn is_valid_subgroup(point: Gaffine) -> bool 
```

### priv_to_pub_key
```rust
/// This function converts a private key to a public key, which is a point on the Baby Jubjub curve.
/// The private key is a Field element which should be sampled uniformly between 0 and bjj_l-1, where bjj_l is the order of the big prime subgroup of Baby Jubjub.
/// Baby Jubjub parameters in affine representation are defined as in ERC-244.
pub fn priv_to_pub_key(private_key: Field) -> Gaffine
```

### exp_elgamal_encrypt
```rust
/// Exponential ElGamal Encryption on Baby Jubjub, plaintext is restricted to u40 as the last step of decryption requires solving the Discrete Logarithm Problem.
/// The randomness parameter should be sampled uniformly between 0 and bjj_l-1 and NEVER reused. bjj_l is the order of the big prime subgroup of Baby Jubjub.
/// Same notations as in https://en.wikipedia.org/wiki/ElGamal_encryption 
/// The public_key point passed as an argument must correspond to a valid public key, i.e an element of the Baby Jubjub curve
pub fn exp_elgamal_encrypt(public_key: Gaffine, plaintext: u40, randomness: Field) -> (Gaffine,Gaffine)
```

### exp_elgamal_decrypt
```rust
/// Exponential ElGamal Decryption on Baby Jubjub, the returned point is an embedding of the plaintext on the curve,
/// so to fully decrypt it, use the Baby-Step Giant-Step implementations in Rust or in JS/WASM which accompany this package.
/// Warning : ciphertext is supposed to be valid (i.e results from an encryption of a u40 with a valid Public Key via `exp_elgamal_encrypt`).
pub fn exp_elgamal_decrypt(private_key : Field, ciphertext: (Gaffine,Gaffine)) -> Gaffine
```

### pack_point
```rust
/// This function converts the orginal public key to its compressed form, i.e from a point on Baby Jubjub to a bytes32.
/// This matches circomlibjs from here: https://github.com/iden3/circomlibjs/blob/4f094c5be05c1f0210924a3ab204d8fd8da69f49/src/babyjub.js#L97
/// The public_key point passed as an argument must correspond to a valid public key, i.e an element of the Baby Jubjub curve.
pub fn pack_point(public_key: Gaffine) -> [u8;32] {
```

### unpack_point
```rust
/// This function converts back the compressed public key to its original form, i.e from a bytes32 to a point on Baby Jubjub
/// This matches circomlibjs from here: https://github.com/iden3/circomlibjs/blob/4f094c5be05c1f0210924a3ab204d8fd8da69f49/src/babyjub.js#L108
/// The packed_public_key array passed as an argument must correspond to a valid public key, i.e an element of the  Baby Jubjub curve
pub fn unpack_point(public_key: [u8; 32]) -> Gaffine 
```

### exp_elgamal_encrypt_packed
```rust
/// Same as exp_elgamal_encrypt but instead of an upacked public_key, takes directly the packed public key as an argument
/// Saves gates because the validity of the public key is checked only once instead of twice (1st when using unpack_point and 2nd in exp_elgamal_encrypt)
pub fn exp_elgamal_encrypt_packed(packed_public_key: [u8; 32], plaintext: u40, randomness: Field) -> (Gaffine,Gaffine)
```

## Disclaimer

This is **experimental software** and is provided on an "as is" and "as available" basis. We **do not give any warranties** and **will not be liable for any losses** incurred through any use of this code base.
