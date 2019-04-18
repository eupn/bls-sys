mod id {
    use bls_sys::{bls_init, BlsId, CurveType};

    #[test]
    pub fn id_serde_roundtrip() {
        bls_init(CurveType::CurveFp254BNb).unwrap();

        let mut id = BlsId::new();
        id.set_int(42);

        let mut buf = [0u8; 32];
        id.serialize(&mut buf).unwrap();

        let mut id2 = BlsId::new();
        id2.deserialize(&buf).unwrap();

        assert_eq!(id, id2);
    }

    #[test]
    pub fn id_dec_str_set() {
        bls_init(CurveType::CurveFp254BNb).unwrap();

        let mut id = BlsId::new();
        id.set_dec_str("42").unwrap();

        let mut id_actual = BlsId::new();
        id_actual.set_int(42);

        assert_eq!(id, id_actual)
    }

    #[test]
    pub fn id_dec_str_get() {
        bls_init(CurveType::CurveFp254BNb).unwrap();

        let mut id = BlsId::new();
        id.set_int(42);

        let dec_str = id.get_dec_str().unwrap();
        assert_eq!("42", &dec_str);
    }

    #[test]
    pub fn id_hex_str_set() {
        bls_init(CurveType::CurveFp254BNb).unwrap();

        let mut id = BlsId::new();
        id.set_hex_str("2a").unwrap();

        let mut id_actual = BlsId::new();
        id_actual.set_int(0x2a); // 42

        assert_eq!(id, id_actual)
    }

    #[test]
    pub fn id_hex_str_get() {
        bls_init(CurveType::CurveFp254BNb).unwrap();

        let mut id = BlsId::new();
        id.set_int(42);

        let dec_str = id.get_hex_str().unwrap();
        assert_eq!("2a", &dec_str);
    }
}

mod secret_key {
    use bls_sys::{bls_init, BlsSecretKey, CurveType};

    #[test]
    pub fn secret_key_serde_roundtrip() {
        bls_init(CurveType::CurveFp254BNb).unwrap();

        let mut secret_key = BlsSecretKey::new();
        secret_key.set_dec_str("42").unwrap();

        let mut buf = [0u8; 32];
        secret_key.serialize(&mut buf).unwrap();

        let mut secret_key2 = BlsSecretKey::new();
        secret_key2.deserialize(&buf).unwrap();

        assert_eq!(secret_key, secret_key2);
    }

    #[test]
    pub fn secret_key_dec_str_set() {
        bls_init(CurveType::CurveFp254BNb).unwrap();

        let mut secret_key = BlsSecretKey::new();
        secret_key.set_dec_str("42").unwrap();

        let mut secret_key_actual = BlsSecretKey::new();
        secret_key_actual.set_dec_str("42").unwrap();

        assert_eq!(secret_key, secret_key_actual)
    }

    #[test]
    pub fn secret_key_dec_str_get() {
        bls_init(CurveType::CurveFp254BNb).unwrap();

        let mut secret_key = BlsSecretKey::new();
        secret_key.set_dec_str("42").unwrap();

        let dec_str = secret_key.get_dec_str().unwrap();
        assert_eq!("42", &dec_str);
    }

    #[test]
    pub fn secret_key_hex_str_set() {
        bls_init(CurveType::CurveFp254BNb).unwrap();

        let mut secret_key = BlsSecretKey::new();
        secret_key.set_hex_str("2a").unwrap();

        let mut secret_key_actual = BlsSecretKey::new();
        secret_key_actual.set_dec_str("42").unwrap();

        assert_eq!(secret_key, secret_key_actual)
    }

    #[test]
    pub fn secret_key_hex_str_get() {
        bls_init(CurveType::CurveFp254BNb).unwrap();

        let mut secret_key = BlsSecretKey::new();
        secret_key.set_dec_str("42").unwrap();

        let dec_str = secret_key.get_hex_str().unwrap();
        assert_eq!("2a", &dec_str);
    }
}

mod signature {
    use bls_sys::{bls_init, BlsSecretKey, CurveType};

    #[test]
    pub fn sign_verify_ok() {
        bls_init(CurveType::Bls12CurveFp381).unwrap();
        let sk = BlsSecretKey::new_random().unwrap();
        let pk = sk.to_public_key();
        let msg = b"test message";
        let sig = sk.sign(&msg[..]);

        assert!(sig.verify(&pk, &msg[..]));
    }

    #[test]
    pub fn sign_verify_fail() {
        bls_init(CurveType::Bls12CurveFp381).unwrap();
        let sk = BlsSecretKey::new_random().unwrap();
        let pk = sk.to_public_key();
        let msg = b"test message";
        let sig = sk.sign(&msg[..]);

        // Shouldn't verify with different message
        let diff_msg = b"different message";
        assert!(!sig.verify(&pk, &diff_msg[..]));

        // Shouldn't verify with different public key
        let diff_pk = BlsSecretKey::new_random().unwrap().to_public_key();
        assert!(!sig.verify(&diff_pk, &msg[..]));
    }
}
