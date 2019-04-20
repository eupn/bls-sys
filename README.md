## bls-sys

_Warning: this library was not crypto/security audited in any way. Use on your own risk._

### Synopsis

This is a FFI binding library to [herumi](https://github.com/herumi)'s [BLS](https://github.com/herumi/bls) library so it can be used from Rust crates
that requires support of [BLS pairing-based cryptography](https://en.wikipedia.org/wiki/Boneh–Lynn–Shacham), especially threshold signature generation and
signature/keys aggregation.

### Prerequisites

* `make` for [bls](bls) and [mcl](mcl) libraries building
* Rust 1.31 or greater (proc. macros are used internally)

### Usage

Add as dependency to your crate's `Cargo.toml`:

```toml
[dependencies]
bls-sys = { git = "https://github.com/eupn/bls-sys" }
```

And then import and initialize before use by selecting elliptic curve of choice:

```rust
use bls_sys::*;

pub fn main() {
    // Initialise once and specify curve that you want to use
    bls_init(CurveType::Bls12CurveFp381).expect("Unable to initialise BLS lib");
    
    // ...
}

```

#### Usage examples

##### Sign message and verify signature

```rust
    use bls_sys::{bls_init, BlsSecretKey, CurveType};

    bls_init(CurveType::Bls12CurveFp381).expect("Unable to initialise BLS lib");
    let sk = BlsSecretKey::new_random().expect("Unable to obtain system randomness");
    let pk = sk.to_public_key();
    let msg = b"test message";
    let sig = sk.sign(&msg[..]);
    
    // Should verify
    assert!(sig.verify(&pk, &msg[..]));
    
    // Shouldn't verify with different message
    let diff_msg = b"different message";
    assert!(!sig.verify(&pk, &diff_msg[..]));

    // Shouldn't verify with different public key
    let diff_pk = BlsSecretKey::new_random().unwrap().to_public_key();
    assert!(!sig.verify(&diff_pk, &msg[..]));
```

##### Signature aggregation

```rust
    use bls_sys::{bls_init, BlsSecretKey, CurveType};

    bls_init(CurveType::Bls12CurveFp381).unwrap();
    
    let sk1 = BlsSecretKey::new_random().unwrap();
    let sk2 = BlsSecretKey::new_random().unwrap();
    let pk1 = sk1.to_public_key();
    let pk2 = sk2.to_public_key();
    
    let msg = b"test message";
    
    let sig1 = sk1.sign(&msg[..]);
    let sig2 = sk2.sign(&msg[..]);
    
    let agg_pk = pk1 + pk2;
    let agg_sig = sig1 + sig2;
    
    // Verify aggregated signature from diff. secret keys by aggregated public key
    assert!(agg_sig.verify(&agg_pk, &msg[..]));
```

#### TODO

- [x] Basic types FFI (`Id`, `PublicKey`, `SecretKey`, `Signature`)
- [x] Ser/De for basic types (`.serialize()`, `.deserialize()`)
- [x] Keypair generation
- [x] Simple signature creation and verification
- [x] `Add` and `Sub` operations on basic types
- [x] Key and Signature aggregation
- [ ] Shamir Secret Sharing
- [ ] Threshold signature generation
- [ ] Proof-of-Possession

#### Alternatives

* Z-Cash's [pairing](https://github.com/zkcrypto/pairing) lib
* POA Network's [threshold_crypto](https://github.com/poanetwork/threshold_crypto) lib