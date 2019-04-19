## bls-sys

_Warning: this library is not crypto/security audited in any way. Use on your own risk._

### Synopsis

This is a FFI binding library to [herumi](https://github.com/herumi)'s [BLS](https://github.com/herumi/bls) library so it can be used from Rust crates
that requires support of [BLS pairing-based cryptography](https://en.wikipedia.org/wiki/Boneh–Lynn–Shacham), especially threshold signature generation and
signature/keys aggregation.

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

#### TODO

- [x] Basic types FFI (`Id`, `PublicKey`, `SecrerKey`, `Signature`)
- [x] Ser/De for basic types (`.serialize()`, `.deserialize()`)
- [x] Keypair generation
- [x] Simple signature creation and verification
- [ ] `Add` and `Sub` operations on basic types
- [ ] Shamir Secret Sharing
- [ ] Threshold signature generation

#### Alternatives

* Z-Cash's [pairing](https://github.com/zkcrypto/pairing) lib
* POA Network's [threshold_crypto](https://github.com/poanetwork/threshold_crypto) lib