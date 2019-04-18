use bls_sys::{bls_id_deserialize, bls_id_is_equal, bls_id_serialize, bls_id_set_int, bls_init, BlsId, CurveType, bls_id_set_dec_str, bls_id_set_hex_str, bls_id_get_dec_str, bls_id_get_hex_str};

#[test]
pub fn id_serde_roundtrip() {
    bls_init(CurveType::CurveFp254BNb);

    let mut id = BlsId::new();
    bls_id_set_int(&mut id, 42);

    let mut buf = [0u8; 32];
    let res = bls_id_serialize(&id, &mut buf).unwrap();

    let mut id2 = BlsId::new();
    let res = bls_id_deserialize(&mut id2, &buf).unwrap();

    assert!(bls_id_is_equal(&id, &id2));
}

#[test]
pub fn id_dec_str_set() {
    bls_init(CurveType::CurveFp254BNb);

    let mut id = BlsId::new();
    bls_id_set_dec_str(&mut id, "42").unwrap();

    let mut id_actual = BlsId::new();
    bls_id_set_int(&mut id_actual, 42);

    assert!(bls_id_is_equal(&id, &id_actual))
}

#[test]
pub fn id_dec_str_get() {
    bls_init(CurveType::CurveFp254BNb);

    let mut id = BlsId::new();
    bls_id_set_int(&mut id, 42);

    let dec_str = bls_id_get_dec_str(&id).unwrap();
    assert_eq!("42", &dec_str);
}

#[test]
pub fn id_hex_str_set() {
    bls_init(CurveType::CurveFp254BNb);

    let mut id = BlsId::new();
    bls_id_set_hex_str(&mut id, "2a").unwrap();

    let mut id_actual = BlsId::new();
    bls_id_set_int(&mut id_actual, 0x2a); // 42

    assert!(bls_id_is_equal(&id, &id_actual))
}

#[test]
pub fn id_hex_str_get() {
    bls_init(CurveType::CurveFp254BNb);

    let mut id = BlsId::new();
    bls_id_set_int(&mut id, 42);

    let dec_str = bls_id_get_hex_str(&id).unwrap();
    assert_eq!("2a", &dec_str);
}
