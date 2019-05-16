mod id {
    use bls_sys::{bls_init, BlsId, CurveType};

    #[test]
    pub fn id_serde_roundtrip() {
        bls_init(CurveType::Bls12CurveFp381).unwrap();

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
        bls_init(CurveType::Bls12CurveFp381).unwrap();

        let mut id = BlsId::new();
        id.set_dec_str("42").unwrap();

        let mut id_actual = BlsId::new();
        id_actual.set_int(42);

        assert_eq!(id, id_actual)
    }

    #[test]
    pub fn id_dec_str_get() {
        bls_init(CurveType::Bls12CurveFp381).unwrap();

        let mut id = BlsId::new();
        id.set_int(42);

        let dec_str = id.get_dec_str().unwrap();
        assert_eq!("42", &dec_str);
    }

    #[test]
    pub fn id_hex_str_set() {
        bls_init(CurveType::Bls12CurveFp381).unwrap();

        let mut id = BlsId::new();
        id.set_hex_str("2a").unwrap();

        let mut id_actual = BlsId::new();
        id_actual.set_int(0x2a); // 42

        assert_eq!(id, id_actual)
    }

    #[test]
    pub fn id_hex_str_get() {
        bls_init(CurveType::Bls12CurveFp381).unwrap();

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
        bls_init(CurveType::Bls12CurveFp381).unwrap();

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
        bls_init(CurveType::Bls12CurveFp381).unwrap();

        let mut secret_key = BlsSecretKey::new();
        secret_key.set_dec_str("42").unwrap();

        let mut secret_key_actual = BlsSecretKey::new();
        secret_key_actual.set_dec_str("42").unwrap();

        assert_eq!(secret_key, secret_key_actual)
    }

    #[test]
    pub fn secret_key_dec_str_get() {
        bls_init(CurveType::Bls12CurveFp381).unwrap();

        let mut secret_key = BlsSecretKey::new();
        secret_key.set_dec_str("42").unwrap();

        let dec_str = secret_key.get_dec_str().unwrap();
        assert_eq!("42", &dec_str);
    }

    #[test]
    pub fn secret_key_hex_str_set() {
        bls_init(CurveType::Bls12CurveFp381).unwrap();

        let mut secret_key = BlsSecretKey::new();
        secret_key.set_hex_str("2a").unwrap();

        let mut secret_key_actual = BlsSecretKey::new();
        secret_key_actual.set_dec_str("42").unwrap();

        assert_eq!(secret_key, secret_key_actual)
    }

    #[test]
    pub fn secret_key_hex_str_get() {
        bls_init(CurveType::Bls12CurveFp381).unwrap();

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
    }
}

mod arithm {
    use bls_sys::{bls_init, BlsSecretKey, CurveType};

    #[test]
    pub fn sec_key_arithm() {
        bls_init(CurveType::Bls12CurveFp381).unwrap();

        let mut sk1 = BlsSecretKey::new();
        sk1.set_dec_str("10").unwrap();

        let mut sk2 = BlsSecretKey::new();
        sk2.set_dec_str("15").unwrap();

        // Test addition
        let agg_sk = sk1.clone() + sk2.clone(); // 10 + 15 = 25
        assert_eq!("25", agg_sk.get_dec_str().unwrap());

        // Test subtraction
        let orig_sk = agg_sk - sk2; // 25 - 15 = 10
        assert_eq!("10", orig_sk.get_dec_str().unwrap());
    }

    #[test]
    pub fn pk_sig_agg() {
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
    }
}

mod secret_sharing {
    use bls_sys::{bls_init, BlsSecretKey, CurveType, BlsId, BlsPublicKey};

    #[test]
    pub fn trivial_secret_sharing() {
        bls_init(CurveType::Bls12CurveFp381).unwrap();

        let mut id = BlsId::new();
        id.set_int(123);

        let sec1 = BlsSecretKey::new_random().unwrap();
        let pub1 = sec1.to_public_key();

        let sec2 = BlsSecretKey::new_share(&sec1, 1, &id).unwrap();
        assert_eq!(sec1, sec2);

        let sec2 = BlsSecretKey::recover(&[sec1.clone()], &[id.clone()], 1).unwrap();
        assert_eq!(sec1, sec2);

        let pub2 = BlsPublicKey::new_share(&pub1, 1, &id).unwrap();
        assert_eq!(pub1, pub2);

        let pub2 = BlsPublicKey::recover(&[pub1.clone()], &[id], 1).unwrap();
        assert_eq!(pub1, pub2);
    }
}