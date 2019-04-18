use libc::{c_int, size_t, uint64_t, uint8_t};
use std::ffi::{CString, CStr};
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

#[repr(C)]
pub struct MclBnFr([uint64_t; MCLBN_FR_UNIT_SIZE as usize]);

impl MclBnFr {
    pub fn new() -> Self {
        Self([0; MCLBN_FR_UNIT_SIZE as usize])
    }
}

#[repr(C)]
pub struct MclBnG1([uint64_t; MCLBN_FR_UNIT_SIZE as usize * 3]);

#[repr(C)]
pub struct MclBnG2([uint64_t; MCLBN_FR_UNIT_SIZE as usize * 2 * 3]);

#[repr(C)]
pub struct MclBnGT([uint64_t; MCLBN_FR_UNIT_SIZE as usize * 12]);

#[repr(C)]
pub struct MclBnFp([uint64_t; MCLBN_FR_UNIT_SIZE as usize]);

#[repr(C)]
pub struct MclBnFp2([MclBnFp; 2]);

pub type BlsId = MclBnFr;

pub type BlsSecretKey = MclBnFr;
pub type BlsPublicKey = MclBnG2;
pub type BlsSignature = MclBnG1;

pub fn bls_init(curve: CurveType) -> Result<(), isize> {
    let res = unsafe { blsInit(curve as c_int, COMPILED_VAR) };

    if res == 0 {
        Ok(())
    } else {
        Err(res as isize)
    }
}

pub fn bls_id_set_int(id: &mut BlsId, x: i32) {
    unsafe {
        blsIdSetInt(id, x);
    }
}

pub fn bls_id_serialize(id: &BlsId, buf: &mut [u8]) -> Result<usize, ()> {
    let size = unsafe { blsIdSerialize(buf.as_mut_ptr(), buf.len(), id) };

    if size == 0 {
        Err(())
    } else {
        Ok(size)
    }
}

pub fn bls_id_deserialize(id: &mut BlsId, buf: &[u8]) -> Result<usize, ()> {
    let size = unsafe { blsIdDeserialize(id, buf.as_ptr(), buf.len()) };

    if size == 0 {
        Err(())
    } else {
        Ok(size)
    }
}

pub fn bls_id_is_equal(lhs: &BlsId, rhs: &BlsId) -> bool {
    let res = unsafe { blsIdIsEqual(lhs, rhs) };

    res == 1
}

pub fn bls_id_set_dec_str(id: &mut BlsId, dec_str: &str) -> Result<(), ()> {
    let buf = dec_str.as_bytes();
    let c_str = CString::new(dec_str);

    match c_str {
        Ok(s) => {
            let res = unsafe { blsIdSetDecStr(id, s.as_ptr(), buf.len()) };

            if res == 0 {
                Ok(())
            } else {
                Err(())
            }
        }
        Err(_) => Err(())?,
    }
}

pub fn bls_id_get_dec_str(id: &BlsId) -> Result<String, ()> {
    let mut buf = [0u8; 128];
    let res = unsafe { blsIdGetDecStr(buf.as_mut_ptr(), buf.len(), id) };
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

pub fn bls_id_set_hex_str(id: &mut BlsId, dec_str: &str) -> Result<(), ()> {
    let buf = dec_str.as_bytes();
    let c_str = CString::new(dec_str);

    match c_str {
        Ok(s) => {
            let res = unsafe { blsIdSetHexStr(id, s.as_ptr(), buf.len()) };

            if res == 0 {
                Ok(())
            } else {
                Err(())
            }
        }
        Err(_) => Err(())?,
    }
}

pub fn bls_id_get_hex_str(id: &BlsId) -> Result<String, ()> {
    let mut buf = [0u8; 128];
    let res = unsafe { blsIdGetHexStr(buf.as_mut_ptr(), buf.len(), id) };
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
