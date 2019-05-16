use libc::{c_int, size_t, uint64_t, uint8_t};
use paste;
use std::ffi::{CStr, CString};
use std::fmt::{Error, Formatter};
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::os::raw::c_char;

pub const MCLBN_FR_UNIT_SIZE: c_int = 4;
pub const MCLBN_FP_UNIT_SIZE: c_int = 6;

#[link(name = "bls384_256")]
extern "C" {
    fn blsInit(curve: c_int, compiled_var: c_int) -> c_int;

    fn blsIdSetInt(id: *mut BlsId, x: c_int);
    fn blsIdSerialize(buf: *mut uint8_t, buf_size: size_t, id: *const BlsId) -> size_t;
    fn blsIdDeserialize(id: *mut BlsId, buf: *const uint8_t, buf_size: size_t) -> size_t;
    fn blsIdIsEqual(lhs: *const BlsId, rhs: *const BlsId) -> size_t;
    fn blsIdSetDecStr(id: *mut BlsId, buf: *const c_char, buf_size: size_t) -> size_t;
    fn blsIdSetHexStr(id: *mut BlsId, buf: *const c_char, buf_size: size_t) -> size_t;
    fn blsIdGetDecStr(buf: *mut uint8_t, buf_size: size_t, id: *const BlsId) -> size_t;
    fn blsIdGetHexStr(buf: *mut uint8_t, buf_size: size_t, id: *const BlsId) -> size_t;

    fn blsSecretKeySerialize(
        buf: *mut uint8_t,
        buf_size: size_t,
        sk: *const BlsSecretKey,
    ) -> size_t;
    fn blsSecretKeyDeserialize(
        sk: *mut BlsSecretKey,
        buf: *const uint8_t,
        buf_size: size_t,
    ) -> size_t;
    fn blsSecretKeyIsEqual(lhs: *const BlsSecretKey, rhs: *const BlsSecretKey) -> size_t;
    fn blsSecretKeySetDecStr(sk: *mut BlsSecretKey, buf: *const c_char, buf_size: size_t)
        -> size_t;
    fn blsSecretKeySetHexStr(sk: *mut BlsSecretKey, buf: *const c_char, buf_size: size_t)
        -> size_t;
    fn blsSecretKeyGetDecStr(
        buf: *mut uint8_t,
        buf_size: size_t,
        sk: *const BlsSecretKey,
    ) -> size_t;
    fn blsSecretKeyGetHexStr(
        buf: *mut uint8_t,
        buf_size: size_t,
        sk: *const BlsSecretKey,
    ) -> size_t;
    fn blsSecretKeySetLittleEndian(
        sk: *mut BlsSecretKey,
        buf: *const uint8_t,
        buf_size: size_t,
    ) -> c_int;
    fn blsSecretKeySetLittleEndianMod(
        sk: *mut BlsSecretKey,
        buf: *const uint8_t,
        buf_size: size_t,
    ) -> c_int;
    fn blsGetPublicKey(pk: *mut BlsPublicKey, sk: *const BlsSecretKey);
    fn blsSecretKeySetByCSPRNG(sk: *mut BlsSecretKey) -> c_int;
    fn blsSecretKeyAdd(this_sk: *mut BlsSecretKey, other: *const BlsSecretKey);
    fn blsSecretKeySub(this_sk: *mut BlsSecretKey, other: *const BlsSecretKey);
    fn blsSecretKeyShare(sk: *mut BlsSecretKey, msk: *const BlsSecretKey, k: size_t, id: *const BlsId) -> c_int;
    fn blsSecretKeyRecover(sk: *mut BlsSecretKey, sk_vec: *const BlsSecretKey, id_vec: *const BlsId, n: size_t) -> c_int;

    fn blsPublicKeySerialize(
        buf: *mut uint8_t,
        buf_size: size_t,
        id: *const BlsPublicKey,
    ) -> size_t;
    fn blsPublicKeyDeserialize(
        id: *mut BlsPublicKey,
        buf: *const uint8_t,
        buf_size: size_t,
    ) -> size_t;
    fn blsPublicKeyIsEqual(lhs: *const BlsPublicKey, rhs: *const BlsPublicKey) -> size_t;
    fn blsPublicKeySetDecStr(id: *mut BlsPublicKey, buf: *const c_char, buf_size: size_t)
        -> size_t;
    fn blsPublicKeySetHexStr(id: *mut BlsPublicKey, buf: *const c_char, buf_size: size_t)
        -> size_t;
    fn blsPublicKeyGetDecStr(
        buf: *mut uint8_t,
        buf_size: size_t,
        id: *const BlsPublicKey,
    ) -> size_t;
    fn blsPublicKeyGetHexStr(
        buf: *mut uint8_t,
        buf_size: size_t,
        pk: *const BlsPublicKey,
    ) -> size_t;
    fn blsPublicKeyAdd(this_pk: *mut BlsPublicKey, other: *const BlsPublicKey);
    fn blsPublicKeySub(this_pk: *mut BlsPublicKey, other: *const BlsPublicKey);
    fn blsPublicKeyShare(pk: *mut BlsPublicKey, mpk: *const BlsPublicKey, k: size_t, id: *const BlsId) -> c_int;
    fn blsPublicKeyRecover(pk: *mut BlsPublicKey, pk_vec: *const BlsPublicKey, id_vec: *const BlsId, n: size_t) -> c_int;

    fn blsSignatureSerialize(
        buf: *mut uint8_t,
        buf_size: size_t,
        id: *const BlsSignature,
    ) -> size_t;
    fn blsSignatureDeserialize(
        id: *mut BlsSignature,
        buf: *const uint8_t,
        buf_size: size_t,
    ) -> size_t;
    fn blsSignatureIsEqual(lhs: *const BlsSignature, rhs: *const BlsSignature) -> size_t;
    fn blsSignatureSetDecStr(id: *mut BlsSignature, buf: *const c_char, buf_size: size_t)
        -> size_t;
    fn blsSignatureSetHexStr(id: *mut BlsSignature, buf: *const c_char, buf_size: size_t)
        -> size_t;
    fn blsSignatureGetDecStr(
        buf: *mut uint8_t,
        buf_size: size_t,
        id: *const BlsSignature,
    ) -> size_t;
    fn blsSignatureGetHexStr(
        buf: *mut uint8_t,
        buf_size: size_t,
        id: *const BlsSignature,
    ) -> size_t;
    fn blsSignatureAdd(this_sig: *mut BlsSignature, other: *const BlsSignature);
    fn blsSignatureSub(this_sig: *mut BlsSignature, other: *const BlsSignature);
    fn blsSignatureRecover(sig: *mut BlsSignature, sig_vec: *const BlsSignature, id_vec: *const BlsId, n: size_t) -> c_int;

    fn blsSign(sig: *mut BlsSignature, sk: *const BlsSecretKey, msg: *const uint8_t, size: size_t);
    fn blsVerify(
        sig: *const BlsSignature,
        pk: *const BlsPublicKey,
        msg: *const uint8_t,
        size: size_t,
    ) -> c_int;
}

const COMPILED_VAR: c_int = MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum CurveType {
    CurveFp254BNb = 0,
    CurveFp382One = 1,
    CurveFp382Two = 2,
    CurveFp462 = 3,
    CurveSNARK1 = 4,
    Bls12CurveFp381 = 5,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct MclBnFr([uint64_t; MCLBN_FR_UNIT_SIZE as usize]);

impl MclBnFr {
    pub fn new() -> Self {
        Self([0; MCLBN_FR_UNIT_SIZE as usize])
    }
}

impl Default for MclBnFr {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct MclBnG1([uint64_t; MCLBN_FP_UNIT_SIZE as usize * 3]);

impl MclBnG1 {
    pub fn new() -> Self {
        Self([0; MCLBN_FP_UNIT_SIZE as usize * 3])
    }
}

impl Default for MclBnG1 {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MclBnG1 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "G1 ({:?})", self.0.iter().collect::<Vec<_>>())
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct MclBnG2([uint64_t; MCLBN_FP_UNIT_SIZE as usize * 2 * 3]);

impl MclBnG2 {
    pub fn new() -> Self {
        Self([0; MCLBN_FP_UNIT_SIZE as usize * 2 * 3])
    }
}

impl std::fmt::Debug for MclBnG2 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "G2 ({:?})", self.0.iter().collect::<Vec<_>>())
    }
}

impl Default for MclBnG2 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct MclBnGT([uint64_t; MCLBN_FP_UNIT_SIZE as usize * 12]);

impl std::fmt::Debug for MclBnGT {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "GT ({:?})", self.0.iter().collect::<Vec<_>>())
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct MclBnFp([uint64_t; MCLBN_FP_UNIT_SIZE as usize]);

#[derive(Debug, Clone)]
#[repr(C)]
pub struct MclBnFp2([MclBnFp; 2]);

#[derive(Debug, Clone)]
#[repr(C)]
pub struct BlsId(MclBnFr);

impl BlsId {
    pub fn set_int(&mut self, x: i32) {
        unsafe {
            blsIdSetInt(self, x);
        }
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct BlsSecretKey(MclBnFr);

impl BlsSecretKey {
    pub fn new_random() -> Result<Self, ()> {
        let mut sk = BlsSecretKey::new();
        let res = unsafe { blsSecretKeySetByCSPRNG(&mut sk) };

        if res == 0 {
            Ok(sk)
        } else {
            Err(())
        }
    }

    pub fn set_little_endian(&mut self, buf: &[u8]) {
        unsafe {
            blsSecretKeySetLittleEndian(self, buf.as_ptr(), buf.len());
        }
    }

    pub fn set_little_endian_mod(&mut self, buf: &[u8]) {
        unsafe {
            blsSecretKeySetLittleEndianMod(self, buf.as_ptr(), buf.len());
        }
    }

    pub fn to_public_key(&self) -> BlsPublicKey {
        let mut pk = BlsPublicKey::new();
        unsafe {
            blsGetPublicKey(&mut pk, self);
        }

        pk
    }

    pub fn sign(&self, msg: &[u8]) -> BlsSignature {
        let mut sig = BlsSignature::new();
        unsafe {
            blsSign(&mut sig, self, msg.as_ptr(), msg.len());
        }

        sig
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct BlsPublicKey(MclBnG2);

#[derive(Debug, Clone)]
#[repr(C)]
pub struct BlsSignature(MclBnG1);

impl BlsSignature {
    pub fn verify(&self, public_key: &BlsPublicKey, msg: &[u8]) -> bool {
        let res = unsafe { blsVerify(self, public_key, msg.as_ptr(), msg.len()) };

        res == 1
    }
}

pub fn bls_init(curve: CurveType) -> Result<(), isize> {
    let res = unsafe { blsInit(curve as c_int, COMPILED_VAR) };

    if res == 0 {
        Ok(())
    } else {
        eprintln!("Error: {}", res);
        Err(res as isize)
    }
}

macro_rules! impl_api {
    ($data_type:ty, $api_name:ident) => {
        paste::item! {
            impl [<Bls $api_name>] {
                pub fn new() -> Self {
                    Self($data_type::new())
                }

                pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ()> {
                    let size = unsafe { [<bls $api_name Serialize>] (buf.as_mut_ptr(), buf.len(), self) };

                    if size == 0 {
                        Err(())
                    } else {
                        Ok(size)
                    }
                }

                pub fn deserialize(&mut self, buf: &[u8]) -> Result<usize, ()> {
                    let size = unsafe { [<bls $api_name Deserialize>] (self, buf.as_ptr(), buf.len()) };

                    if size == 0 {
                        Err(())
                    } else {
                        Ok(size)
                    }
                }

                pub fn set_dec_str(&mut self, dec_str: &str) -> Result<(), ()> {
                    let buf = dec_str.as_bytes();
                    let c_str = CString::new(dec_str);

                    match c_str {
                        Ok(s) => {
                            let res = unsafe { [<bls $api_name SetDecStr>] (self, s.as_ptr(), buf.len()) };

                            if res == 0 {
                                Ok(())
                            } else {
                                Err(())
                            }
                        }
                        Err(_) => Err(())?,
                    }
                }

                pub fn get_dec_str(&self) -> Result<String, ()> {
                    let mut buf = [0u8; 128];
                    let res = unsafe { [<bls $api_name GetDecStr>] (buf.as_mut_ptr(), buf.len(), self) };
                    if res == 0 {
                        Err(())
                    } else {
                        let mut buf = buf.iter().map(|c| *c)
                            .take_while(|n| *n != 0)
                            .collect::<Vec<u8>>();
                        buf.push(0u8); // Append null-terminator

                        let s = CStr::from_bytes_with_nul(&buf);
                        if let Ok(s) = s {
                            Ok(s.to_string_lossy().to_string())
                        } else {
                            Err(())
                        }
                    }
                }

                pub fn set_hex_str(&mut self, dec_str: &str) -> Result<(), ()> {
                    let buf = dec_str.as_bytes();
                    let c_str = CString::new(dec_str);

                    match c_str {
                        Ok(s) => {
                            let res = unsafe { [<bls $api_name SetHexStr>] (self, s.as_ptr(), buf.len()) };

                            if res == 0 {
                                Ok(())
                            } else {
                                Err(())
                            }
                        }
                        Err(_) => Err(())?,
                    }
                }

                pub fn get_hex_str(&self) -> Result<String, ()> {
                    let mut buf = [0u8; 128];
                    let res = unsafe { [<bls $api_name GetHexStr>] (buf.as_mut_ptr(), buf.len(), self) };
                    if res == 0 {
                        Err(())
                    } else {
                        let mut buf = buf.iter().map(|c| *c)
                            .take_while(|n| *n != 0)
                            .collect::<Vec<u8>>();
                        buf.push(0u8);

                        let s = CStr::from_bytes_with_nul(&buf);
                        if let Ok(s) = s {
                            Ok(s.to_string_lossy().to_string())
                        } else {
                            Err(())
                        }
                    }
                }
            }

            impl PartialEq for [<Bls $api_name>] {
                fn eq(&self, other: &Self) -> bool {
                    let res = unsafe { [<bls $api_name IsEqual>](self, other) };
                    res == 1
                }
            }

            impl Eq for [<Bls $api_name>] {}

            impl Default for [<Bls $api_name>] {
                fn default() -> Self {
                    Self::new()
                }
            }
        }
    }
}

macro_rules! impl_ops {
    ($api_name:ident) => {
        paste::item! {
            impl Add for [<Bls $api_name>] {
                type Output = [<Bls $api_name>];
                fn add(mut self, other: [<Bls $api_name>]) -> Self::Output {
                    unsafe {
                        [<bls $api_name Add>](&mut self, &other);
                    }

                    self
                }
            }

            impl AddAssign for [<Bls $api_name>] {
                fn add_assign(&mut self, other: [<Bls $api_name>]) {
                    unsafe {
                        [<bls $api_name Add>](self, &other);
                    }
                }
            }

            impl Sub for [<Bls $api_name>] {
                type Output = [<Bls $api_name>];
                fn sub(mut self, other: [<Bls $api_name>]) -> Self::Output {
                    unsafe {
                        [<bls $api_name Sub>](&mut self, &other);
                    }

                    self
                }
            }

            impl SubAssign for [<Bls $api_name>] {
                fn sub_assign(&mut self, other: [<Bls $api_name>]) {
                    unsafe {
                        [<bls $api_name Sub>](self, &other);
                    }
                }
            }
        }
    };
}

macro_rules! impl_sharing {
    ($api_name:ident) => {
        paste::item! {
            impl [<Bls $api_name>] {
                pub fn new_share(msk: &[<Bls $api_name>], num_shares: usize, id: &BlsId) -> Result<Self, ()> {
                    let mut key = [<Bls $api_name>]::new();

                    let res = unsafe { [<bls $api_name Share>](&mut key, msk, num_shares, id) };

                    if res == 0 {
                        Ok(key)
                    } else {
                        Err(())
                    }
                }
            }
        }
    }
}

macro_rules! impl_recover {
    ($api_name:ident) => {
        paste::item! {
            impl [<Bls $api_name>] {
                pub fn recover(shares: &[[<Bls $api_name>]], ids: &[BlsId], num_shares: usize) -> Result<Self, ()> {
                    let mut key = [<Bls $api_name>]::new();

                    let res = unsafe { [<bls $api_name Recover>](&mut key, shares.as_ptr(), ids.as_ptr(), num_shares) };

                    if res == 0 {
                        Ok(key)
                    } else {
                        Err(())
                    }
                }
            }
        }
    }
}

// Implement API methods for library types
impl_api!(MclBnFr, Id);
impl_api!(MclBnFr, SecretKey);
impl_api!(MclBnG2, PublicKey);
impl_api!(MclBnG1, Signature);

// Implement arithmetic operations for supported types
impl_ops!(SecretKey);
impl_ops!(PublicKey);
impl_ops!(Signature);

// Implement secret sharing APIs for supported types
impl_sharing!(SecretKey);
impl_sharing!(PublicKey);

// Implement secret recovery APIs for supported types
impl_recover!(SecretKey);
impl_recover!(PublicKey);
impl_recover!(Signature);
