#![recursion_limit = "1024"]

use libc::{c_int, size_t, uint64_t, uint8_t};
use paste;
use std::ffi::{CStr, CString};
use std::fmt::{Error, Formatter};
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
        id: *const BlsSecretKey,
    ) -> size_t;
    fn blsSecretKeyDeserialize(
        id: *mut BlsSecretKey,
        buf: *const uint8_t,
        buf_size: size_t,
    ) -> size_t;
    fn blsSecretKeyIsEqual(lhs: *const BlsSecretKey, rhs: *const BlsSecretKey) -> size_t;
    fn blsSecretKeySetDecStr(id: *mut BlsSecretKey, buf: *const c_char, buf_size: size_t)
        -> size_t;
    fn blsSecretKeySetHexStr(id: *mut BlsSecretKey, buf: *const c_char, buf_size: size_t)
        -> size_t;
    fn blsSecretKeyGetDecStr(
        buf: *mut uint8_t,
        buf_size: size_t,
        id: *const BlsSecretKey,
    ) -> size_t;
    fn blsSecretKeyGetHexStr(
        buf: *mut uint8_t,
        buf_size: size_t,
        id: *const BlsSecretKey,
    ) -> size_t;

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
        id: *const BlsPublicKey,
    ) -> size_t;

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

#[derive(Debug)]
#[repr(C)]
pub struct MclBnFr([uint64_t; MCLBN_FR_UNIT_SIZE as usize]);

impl MclBnFr {
    pub fn new() -> Self {
        Self([0; MCLBN_FR_UNIT_SIZE as usize])
    }
}

#[repr(C)]
pub struct MclBnG1([uint64_t; MCLBN_FR_UNIT_SIZE as usize * 3]);

impl MclBnG1 {
    pub fn new() -> Self {
        Self([0; MCLBN_FR_UNIT_SIZE as usize * 3])
    }
}

impl std::fmt::Debug for MclBnG1 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "G1 ({:?})", self.0.iter().collect::<Vec<_>>())
    }
}

#[repr(C)]
pub struct MclBnG2([uint64_t; MCLBN_FR_UNIT_SIZE as usize * 2 * 3]);

impl MclBnG2 {
    pub fn new() -> Self {
        Self([0; MCLBN_FR_UNIT_SIZE as usize * 2 * 3])
    }
}

impl std::fmt::Debug for MclBnG2 {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "G2 ({:?})", self.0.iter().collect::<Vec<_>>())
    }
}

#[repr(C)]
pub struct MclBnGT([uint64_t; MCLBN_FR_UNIT_SIZE as usize * 12]);

impl std::fmt::Debug for MclBnGT {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "GT ({:?})", self.0.iter().collect::<Vec<_>>())
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct MclBnFp([uint64_t; MCLBN_FR_UNIT_SIZE as usize]);

#[derive(Debug)]
#[repr(C)]
pub struct MclBnFp2([MclBnFp; 2]);

#[derive(Debug)]
#[repr(C)]
pub struct BlsId(MclBnFr);

#[derive(Debug)]
#[repr(C)]
pub struct BlsSecretKey(MclBnFr);

#[derive(Debug)]
#[repr(C)]
pub struct BlsPublicKey(MclBnG2);

#[derive(Debug)]
#[repr(C)]
pub struct BlsSignature(MclBnG1);

pub fn bls_init(curve: CurveType) -> Result<(), isize> {
    let res = unsafe { blsInit(curve as c_int, COMPILED_VAR) };

    if res == 0 {
        Ok(())
    } else {
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
                        buf.push(0u8);

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
        }
    }
}

impl_api!(MclBnFr, Id);
impl_api!(MclBnFr, SecretKey);
impl_api!(MclBnG2, PublicKey);
impl_api!(MclBnG1, Signature);

impl BlsId {
    pub fn set_int(&mut self, x: i32) {
        unsafe {
            blsIdSetInt(self, x);
        }
    }
}
