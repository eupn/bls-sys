use bls_sys::{bls_id_deserialize, bls_id_serialize, bls_id_set_int, bls_init, BlsId, CurveType};

pub fn main() {
    println!("{:?}", bls_init(CurveType::CurveFp254BNb));

    let mut id = BlsId::new();
    bls_id_set_int(&mut id, 42);

    let mut buf = [0u8; 32];
    let res = bls_id_serialize(&id, &mut buf);
    println!("Serialize: {:?}, {:?}", res, buf);

    let res = bls_id_deserialize(&mut id, &buf);
    println!("Deserialize: {:?}", res);
}
