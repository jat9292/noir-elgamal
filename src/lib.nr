use dep::std::ec::tecurve::affine::Curve as AffineCurve;
use dep::std::ec::tecurve::affine::Point as Gaffine;
use dep::std::collections::vec::Vec;
use dep::std;
use dep::std::ec;
use dep::std::eddsa::lt_bytes32;

global bjj_a = 168700;
global bjj_d = 168696;
global bjj_generator_x = 995203441582195749578291179787384436505546430278305826713579947235728471134;
global bjj_generator_y = 5472060717959818805561601436314318772137091100104008585924551046643952123905;
global bjj_basept_x    = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
global bjj_basept_y    = 16950150798460657717958625567821834550301663161624707787222815936182638968203;
global bjj_l = 2736030358979909402780800718157159386076813972158567259200215660948447373041; // order of the big prime subgroup of the curve = order of basept

pub fn get_affine_curve() -> AffineCurve {
  AffineCurve::new(bjj_a, bjj_d, Gaffine::new(bjj_generator_x, bjj_generator_y))
}

pub fn get_base_point() -> Gaffine {
  Gaffine::new(bjj_basept_x, bjj_basept_y)
}

/// This function checks that a point is in the big prime subgroup of the Baby Jubjub curve. 
/// It is used to check that a public key is valid.
pub fn is_valid_subgroup(point: Gaffine) -> bool {
  let bjj_affine = get_affine_curve();
  let is_on_curve = bjj_affine.contains(point); // checks the point is on bjj
  let is_in_big_prime_subgroup = bjj_affine.mul(bjj_l, point).is_zero(); // checks the point is in the big prime subgroup of bjj
  is_on_curve & is_in_big_prime_subgroup
}


/// This function converts a private key to a public key, which is a point on the Baby Jubjub curve.
/// The private key is a Field element which should be sampled uniformly between 0 and bjj_l-1, where bjj_l is the order of the big prime subgroup of Baby Jubjub.
/// Baby Jubjub parameters in affine representation are defined as in ERC-244.
pub fn priv_to_pub_key(private_key: Field) -> Gaffine
{
  let bjj_affine = get_affine_curve();
  let base_pt = get_base_point();
  bjj_affine.mul(private_key, base_pt)
}

/// Exponential ElGamal Encryption on Baby Jubjub, plaintext is restricted to u40 as the last step of decryption requires solving the Discrete Logarithm Problem.
/// The randomness parameter should be sampled uniformly between 0 and bjj_l-1 and NEVER reused. bjj_l is the order of the big prime subgroup of Baby Jubjub.
/// Same notations as in https://en.wikipedia.org/wiki/ElGamal_encryption 
/// The public_key point passed as an argument must correspond to a valid public key, i.e an element of the Baby Jubjub curve
pub fn exp_elgamal_encrypt(public_key: Gaffine, plaintext: u40, randomness: Field) -> (Gaffine,Gaffine)
{
  assert(is_valid_subgroup(public_key)); // checks the public key is valid
  let bjj_affine = get_affine_curve();
  let base_pt = get_base_point();
  let C1: Gaffine = bjj_affine.mul(randomness, base_pt);
  let plain_embedded: Gaffine = bjj_affine.mul(plaintext as Field, base_pt);
  let shared_secret: Gaffine = bjj_affine.mul(randomness, public_key);
  let C2: Gaffine = bjj_affine.add(shared_secret, plain_embedded);
  (C1,C2)
}

/// Exponential ElGamal Decryption on Baby Jubjub, the returned point is an embedding of the plaintext on the curve,
/// so to fully decrypt it, use the Baby-Step Giant-Step implementations in Rust or in JS/WASM which accompany this package
/// Warning : ciphertext is supposed to be valid (i.e results from an encryption of a u40 with a valid Public Key via `exp_elgamal_encrypt`)
pub fn exp_elgamal_decrypt(private_key : Field, ciphertext: (Gaffine,Gaffine)) -> Gaffine
{
  let bjj_affine = get_affine_curve();
  let shared_secret = bjj_affine.mul(private_key,ciphertext.0);
  let plain_embedded = bjj_affine.subtract(ciphertext.1,shared_secret);
  plain_embedded // give this embedded plaintext as input to the Baby-Step Giant-Step algorithm to get back the original plaintext
}

/// This function converts the orginal public key to its compressed form, i.e from a point on Baby Jubjub to a bytes32.
/// This matches circomlibjs from here: https://github.com/iden3/circomlibjs/blob/4f094c5be05c1f0210924a3ab204d8fd8da69f49/src/babyjub.js#L97
/// The public_key point passed as an argument must correspond to a valid public key, i.e an element of the Baby Jubjub curve.
pub fn pack_point(public_key: Gaffine) -> [u8;32] {
  assert(is_valid_subgroup(public_key), "The public key is not a point on the Baby Jubjub big subgroup"); // checks the public key is valid

  let mut array: [u8;32] = [0;32];
  let mut y = public_key.y.to_le_bytes(32);
  for i in 0..32 {
    array[i] = y[i];
  }

  let pm1d2 = -1 / 2;

  if(lt_bytes32(pm1d2, public_key.x))
  {
    array[31] = array[31] | 0x80;
  }
  array
}

/// This function converts back the compressed public key to its original form, i.e from a bytes32 to a point on Baby Jubjub
/// This matches circomlibjs from here: https://github.com/iden3/circomlibjs/blob/4f094c5be05c1f0210924a3ab204d8fd8da69f49/src/babyjub.js#L108
/// The packed_public_key array passed as an argument must correspond to a valid public key, i.e an element of the  Baby Jubjub curve
pub fn unpack_point(public_key: [u8; 32]) -> Gaffine 
{
  let mut y_array = public_key;
  let mut point: Gaffine = Gaffine::new(0,0);
  let mut sign = false;
  if((y_array[31] & 0x80) != 0) {
    sign = true;
    y_array[31] &= 0x7f;
  }

  point.y = from_rpr_le(y_array);
  let recovered_y_slice = point.y.to_le_bytes(32); 
  let mut recovered_y_array: [u8;32] = [0;32];
  for i in 0..32 {
     recovered_y_array[i]=recovered_y_slice[i];
  }
  assert(recovered_y_array==y_array,"The packed public key is invalid"); // Important check to get unicity of the packed public key, otherwise a malicious user could generate several packed keys for the same unpacked public key by adding a multiple of p to y

  let mut y2 = point.y * point.y;
  let xa = 1-y2;
  let xb = bjj_a - (bjj_d * y2);
  let x2 = xa / xb;
  point.x = ec::sqrt(x2);

  let pm1d2 = -1 / 2;
  let sign2 = lt_bytes32(pm1d2, point.x);

  if(sign!=sign2) {  // discrepancy compared to circomlibjs here probably due to the Montgomery modular form conversion in circomlibjs/ffwasm
     point.x = -point.x;
  } 

  assert(is_valid_subgroup(point), "The public key is not a point on the Baby Jubjub big subgroup"); // checks the public key is valid
  point // the unpacked public key
}


/// Same as exp_elgamal_encrypt but instead of an upacked public_key, takes directly the packed public key as an argument
/// Saves gates because the validity of the public key is checked only once instead of twice (1st when using unpack_point and 2nd in exp_elgamal_encrypt)
pub fn exp_elgamal_encrypt_packed(packed_public_key: [u8; 32], plaintext: u40, randomness: Field) -> (Gaffine,Gaffine)
{
  let mut y_array = packed_public_key;
  let mut public_key: Gaffine = Gaffine::new(0,0);
  let mut sign = false;
  if((y_array[31] & 0x80) != 0) {
    sign = true;
    y_array[31] &= 0x7f;
  }

  public_key.y = from_rpr_le(y_array);
  let recovered_y_slice = public_key.y.to_le_bytes(32); 
  let mut recovered_y_array: [u8;32] = [0;32];
  for i in 0..32 {
     recovered_y_array[i]=recovered_y_slice[i];
  }
  assert(recovered_y_array==y_array,"The packed public key is invalid"); // Important check to get unicity of the packed public key, otherwise a malicious user could generate several packed keys for the same unpacked public key by adding a multiple of p to y

  let mut y2 = public_key.y * public_key.y;
  let xa = 1-y2;
  let xb = bjj_a - (bjj_d * y2);
  let x2 = xa / xb;
  public_key.x = ec::sqrt(x2);

  let pm1d2 = -1 / 2;

  let sign2 = lt_bytes32(pm1d2, public_key.x);

  if(sign!=sign2) { // discrepancy compared to circomlibjs here probably due to the Montgomery modular form conversion in circomlibjs/ffwasm
     public_key.x = -public_key.x;
  } 

  assert(is_valid_subgroup(public_key), "The public key is not a point on the Baby Jubjub big subgroup"); // checks the public key is valid

  let bjj_affine = get_affine_curve();
  let base_pt = get_base_point();
  let C1: Gaffine = bjj_affine.mul(randomness, base_pt);
  let plain_embedded: Gaffine = bjj_affine.mul(plaintext as Field, base_pt);
  let shared_secret: Gaffine = bjj_affine.mul(randomness, public_key);
  let C2: Gaffine = bjj_affine.add(shared_secret, plain_embedded);
  (C1,C2)
}

/// translated from here: https://github.com/iden3/ffjavascript/blob/d1cd4ae32170aedd000865f0828b78a15df6f06f/src/scalar.js#L215
/// and inspired by this: https://gist.github.com/signorecello/dad41f8b90ae48c7355bfd1f34f8885b
fn from_rpr_le(public_key: [u8;32]) -> Field {
  let mut y : Field = 0;
  let mut v : Field = 1;
  for i in 0..32 {
      y += public_key[i] as Field * v;
      v *= 256;
  }
  y
}

#[test]
fn test_main() {
  let message: u40 = 943594123598;
  let private_key: Field = 0x04c330a81537c0d29cc09e8b2b9c43fc5fb5a9d244ab741fc88dff3d40dbd75c; // chosen randomly between 0 and bjj_l-1
  let randomness: Field = 0x010fe5884a7852054a21e21e549520352f563f03d3f79e66a2d75fbd2a21d5cf; // chosen randomly between 0 and bjj_l-1, and never reused

  let public_key: Gaffine = priv_to_pub_key(private_key);
  let ciphertext: (Gaffine,Gaffine) = exp_elgamal_encrypt(public_key, message, randomness);
  let decryption = exp_elgamal_decrypt(private_key, ciphertext); // in embedded form (before the baby-step giant-step application)

  let bjj_affine: AffineCurve = get_affine_curve();
  let base_pt: Gaffine = get_base_point();
  let plain_embedded: Gaffine = bjj_affine.mul(message as Field,base_pt);

  assert(plain_embedded.x == decryption.x);
  assert(plain_embedded.y == decryption.y);
}

#[test]
fn test_pack_point(){
  let private_key = 0x0510bae26a9b59ebad67a4324c944b1910a778e8481d7f08ddba6bcd2b94b2c4;
  let pub_key: Gaffine = priv_to_pub_key(private_key);
  let packed_pub_key = [0xdc, 0x9f, 0x9f, 0xdb, 0x74, 0x6d, 0x0f, 0x07, 0xb0, 0x04, 0xcc, 0x43, 0x16, 0xe3, 0x49, 0x5a, 0x58, 0x57, 0x0b, 0x90, 0x66, 0x14, 0x99, 0xf8, 0xa6, 0xa6, 0x69, 0x6f, 0xf4, 0x15, 0x6b, 0xaa];//generated via circomlibjs
  let computed_packed_key = pack_point(pub_key);
  assert(computed_packed_key == packed_pub_key);

  let private_key2 = 0x03d7c10d654c601b60f2380551b4782896335c48f5d56662b1d0604dd22c8568;
  let pub_key2: Gaffine = priv_to_pub_key(private_key2);
  let packed_pub_key2 = [0x0c, 0x07, 0x99, 0x9c, 0x15, 0xd4, 0x06, 0xbc, 0x08, 0xd7, 0xf3, 0xf3, 0x1f, 0x62, 0xce, 0xdb, 0xc8, 0x9e, 0xbf, 0x3a, 0x53, 0xff, 0x4d, 0x3b, 0xf7, 0xe2, 0xd0, 0xdd, 0xa9, 0x31, 0x49, 0x04];//generated via circomlibjs
  let computed_packed_key2 = pack_point(pub_key2);
  assert(computed_packed_key2 == packed_pub_key2);

  let private_key3 = 0x032336193e8d6ebf273828eb9d6600badbc7cd795c639dbe364307cd121473f2;
  let pub_key3: Gaffine = priv_to_pub_key(private_key3);
  let packed_pub_key3 = [0x29, 0x48, 0x3d, 0xe5, 0xe8, 0x1d, 0xe9, 0x89, 0x3b, 0x56, 0x58, 0xd6, 0x05, 0x01, 0xa4, 0x56, 0x19, 0x8f, 0xd4, 0xbb, 0x39, 0xe4, 0x91, 0x6c, 0x2e, 0x30, 0xf2, 0x42, 0x23, 0xdf, 0xf0, 0xa6];//generated via circomlibjs
  let computed_packed_key3 = pack_point(pub_key3);
  assert(computed_packed_key3 == packed_pub_key3);
}

#[test]
fn test_pack_unpack_point() {
  let private_keys: [Field] = [0x01e5cc52b94418c1d361a3479870df1f46fc4b3e697153843505053dd8b092da,0x05f53084112e74844b82f7cffe0ca07230681243ec3c77d53a6f31f5b04f7c4a,
                              0x04edd04fa218f3b0f32e109696a00baeb5f5b5bc6082b9dd53ff1ad1efe48f29,0x00edd199d52b82a65e7aaf6951f792462a84680022e139d8acf1c07d5168a827,
                              0x01975e987782456b7e73a34835934b6a20c196f750bc7390c0f7d8303b469f7e];
  for private_key in private_keys {
    let public_key: Gaffine = priv_to_pub_key(private_key);
    let packed_pub_key = pack_point(public_key);
    let point = unpack_point(packed_pub_key);
    assert((point.x == public_key.x) & (point.y == public_key.y)); // check that unpack_point(packed_pub_key) always returns the original public key
    }
}

#[test(should_fail_with = "The packed public key is invalid")]
fn test_packed_key_unicity(){
  let mut invalid_packed_public_key : [u8;32] = [0;32];

  let private_key = 0x04d73359c9166e49aafaf9a4852eaa4dceb2c26878196b10e9048004ff5cc20c;
  let pub_key = priv_to_pub_key(private_key);

  let valid_packed_public_key = pack_point(pub_key);
  
  /// Computing a different packed public key which should not be valid, by adding p to the y coordinate :
  // Previosuly could be computed when we imported BigUint via : 
  // let pBig = (BigUint56::from_bytes((-1).to_le_bytes(32)).add(BigUint56::from_bytes((1).to_le_bytes(32))));
  // let yPluspBig = BigUint56::from_bytes(pub_key.y.to_le_bytes(32)).add(pBig); // A user tries to cheat by generating an invalid packed public key by adding p to y
  // Now we hardcode the result in the test : (alternatively we can compute it in Typescript)
  let y = [0xf3, 0xde, 0xb3, 0xbd, 0x36, 0x14, 0x67, 0x9c, 0x55, 0xba, 0x4c, 0xa2, 0x3f, 0xb0, 0xc6, 0x3b, 0x3d, 0xfd, 0xec, 0x4e, 0x10, 0x9d, 0x83, 0x84, 0x53, 0x92, 0xcc, 0x46, 0xc2, 0x30, 0x29, 0x4d];

  for i in 0..32 {
    invalid_packed_public_key[i] = y[i];
  }
  let pm1d2 = -1 / 2;

  if(lt_bytes32(pm1d2, pub_key.x))
  {
    invalid_packed_public_key[31] = invalid_packed_public_key[31] | 0x80;
  }
  
  assert(valid_packed_public_key!=invalid_packed_public_key); /// checks that the newly computed packed public key is different from the original one
  assert((unpack_point(valid_packed_public_key).x==pub_key.x) & (unpack_point(valid_packed_public_key).y==pub_key.y)); // this should succeed
  assert((unpack_point(invalid_packed_public_key).x==pub_key.x) & (unpack_point(invalid_packed_public_key).y==pub_key.y)); // this should fail with `The packed public key is invalid`

}

#[test]
fn test_encrypt(){
  let x: u40 = 5;
  let bjj_affine = get_affine_curve();
  let base_pt = get_base_point();
  let embedded_x = bjj_affine.mul(x as Field, base_pt);

  let private_key = 0x04d73359c9166e49aafaf9a4852eaa4dceb2c26878196b10e9048004ff5cc20c;
  let pub_key: Gaffine = priv_to_pub_key(private_key);

  let randomness = 0x03f90f366f9fd55bb1335eac3b11f2190f2ce9ff1769db241edaa7774136099b;
  let encrypted_point = exp_elgamal_encrypt(pub_key, x, randomness);
  let decrypted_point = exp_elgamal_decrypt(private_key, encrypted_point);

  assert(decrypted_point.x == embedded_x.x);
  assert(decrypted_point.y == embedded_x.y);

  let packed = pack_point(pub_key);
  let unpacked = unpack_point(packed);

  let randomness2 = 0x0210a43c3e46d9ca877d57b2ff67ea8fff900031c57c478c0c03c2d432b2e2a5;
  let encrypted_with_unpacked = exp_elgamal_encrypt(unpacked, x, randomness2);
  let decrypted_with_unpacked = exp_elgamal_decrypt(private_key, encrypted_with_unpacked);

  assert(decrypted_with_unpacked.x == embedded_x.x);
  assert(decrypted_with_unpacked.y == embedded_x.y);
}

#[test]
fn test_encrypt_packed(){
  let x: u40 = 5;
  let bjj_affine = get_affine_curve();
  let base_pt = get_base_point();
  let embedded_x = bjj_affine.mul(x as Field, base_pt);

  let private_key = 0x03de9c86d98bf24ffaac6e38fb55c8c45f73a33bdd4b2d8c904f2c34971356c2;
  let pub_key: Gaffine = priv_to_pub_key(private_key);

  let packed = pack_point(pub_key);

  let randomness = 0x030cffca80ca4344e54e436fc5a03ae8e884b8f3edcb780702599e1951e8aa62;
  let encrypted_with_packed = exp_elgamal_encrypt_packed(packed, x, randomness);
  let decrypted_with_packed = exp_elgamal_decrypt(private_key, encrypted_with_packed);

  assert(decrypted_with_packed.x == embedded_x.x);
  assert(decrypted_with_packed.y == embedded_x.y);
}