use dep::std::ec::tecurve::affine::Curve as AffineCurve;
use dep::std::ec::tecurve::affine::Point as Gaffine;
use dep::std::collections::vec::Vec;
use dep::std;
use dep::biguint::BigUint56;
use dep::std::ec;

global bjj_a = 168700;
global bjj_d = 168696;
global bjj_generator_x = 995203441582195749578291179787384436505546430278305826713579947235728471134;
global bjj_generator_y = 5472060717959818805561601436314318772137091100104008585924551046643952123905;
global bjj_basept_x    = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
global bjj_basept_y    = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

pub fn get_affine_curve() -> AffineCurve {
  AffineCurve::new(bjj_a, bjj_d, Gaffine::new(bjj_generator_x, bjj_generator_y))
}

pub fn get_base_point() -> Gaffine {
  Gaffine::new(bjj_basept_x, bjj_basept_y)
}

// This function converts a private key to a public key, which is a point on the Baby Jubjub curve
// The private key is a Field element which should be sampled uniformly between 0 and l-1, where l is the order of the prime subgroup of Baby Jubjub, l=2736030358979909402780800718157159386076813972158567259200215660948447373041
// Baby Jubjub parameters in affine representation are defined as in ERC-244
pub fn priv_to_pub_key(private_key: Field) -> Gaffine
{
 let bjj_affine = get_affine_curve();
 let base_pt = get_base_point();
 bjj_affine.mul(private_key, base_pt)
}

// Exponential ElGamal Encryption on Baby Jubjub, the plaintext is restricted to u40 because the last step of decryption requires to solve the Discrete Logarithm Problem
// same notations as in https://en.wikipedia.org/wiki/ElGamal_encryption 
// Warning : the public_key point passed as an argument must correspond to a valid public key, i.e an element of the Baby Jubjub curve
pub fn exp_elgamal_encrypt(public_key: Gaffine, plaintext: u40, randomness: Field) -> (Gaffine,Gaffine)
{
 let bjj_affine = get_affine_curve();
 assert(bjj_affine.contains(public_key)); // checks the public key is valid
 let base_pt = get_base_point();
 let C1: Gaffine = bjj_affine.mul(randomness, base_pt);
 let plain_embedded: Gaffine = bjj_affine.mul(plaintext as Field, base_pt);
 let shared_secret: Gaffine = bjj_affine.mul(randomness, public_key);
 let C2: Gaffine = bjj_affine.add(shared_secret, plain_embedded);
 (C1,C2)
}

// Exponential ElGamal Decryption on Baby Jubjub, the returned point is an embedding of the plaintext on the curve,
// so to fully decrypt it, use the Baby-Step Giant-Step implementations in Rust or in WASM which accompany this package
pub fn exp_elgamal_decrypt(private_key : Field, ciphertext: (Gaffine,Gaffine)) -> Gaffine
{
 let bjj_affine = get_affine_curve();
 let shared_secret = bjj_affine.mul(private_key,ciphertext.0);
 let plain_embedded = bjj_affine.subtract(ciphertext.1,shared_secret);
 plain_embedded // give this embedded plaintext as input to the Baby-Step Giant-Step algorithm to get back the original plaintext
}

// This matches circomlibjs
// from here: https://github.com/iden3/circomlibjs/blob/4f094c5be05c1f0210924a3ab204d8fd8da69f49/src/babyjub.js#L97
// Warning : the public_key point passed as an argument must correspond to a valid public key, i.e an element of the Baby Jubjub curve
pub fn pack_point(public_key: Gaffine) -> [u8;32] {
  let bjj_affine = get_affine_curve();
  assert(bjj_affine.contains(public_key)); // checks the public key is valid

  let mut array: [u8;32] = [0;32];
  let mut y = public_key.y.to_le_bytes(32);
  for i in 0..32 {
    array[i] = y[i];
  }

  let pm1d2 = -1 / 2;

  if(BigUint56::from_bytes(public_key.x.to_le_bytes(32))
      .gt(BigUint56::from_bytes(pm1d2.to_le_bytes(32))))
  {
    array[31] = array[31] | 0x80;
  }
  array
}

// This matches circomlibjs
// from here: https://github.com/iden3/circomlibjs/blob/4f094c5be05c1f0210924a3ab204d8fd8da69f49/src/babyjub.js#L108
// Warning : the packed_public_key array passed as an argument must correspond to a valid public key, i.e an element of the  Baby Jubjub curve
pub fn unpack_point(mut public_key: [u8; 32]) -> Gaffine 
{
  let mut point: Gaffine = Gaffine::new(0,0);
  let mut sign = false;
  if((public_key[31] & 0x80) != 0) {
    sign = true;
    public_key[31] &= 0x7f;
  }
  point.y = from_rpr_le(public_key);

  let mut y2 = point.y * point.y;
  let xa = 1-y2;
  let xb = bjj_a - (bjj_d * y2);
  let x2 = xa / xb;
  point.x = ec::sqrt(x2);

  let pm1d2 = -1 / 2;
  let sign2 = (BigUint56::from_bytes(point.x.to_le_bytes(32))
      .gt(BigUint56::from_bytes(pm1d2.to_le_bytes(32))));

  if(sign!=sign2) {
     point.x = -point.x;
  } 
  let bjj_affine = get_affine_curve();
  assert(bjj_affine.contains(point)); // checks the public key is valid
  point
}


// Same as exp_elgamal_encrypt but instead of an upacked public_key, takes directly the packed public key as an argument
// Saves gates because the validity of the public key is checked only once instead of twice (1st when using unpack_point and 2nd in exp_elgamal_encrypt)
pub fn exp_elgamal_encrypt_packed(mut packed_public_key: [u8; 32], plaintext: u40, randomness: Field) -> (Gaffine,Gaffine)
{
  let mut public_key: Gaffine = Gaffine::new(0,0);
  let mut sign = false;
  if((packed_public_key[31] & 0x80) != 0) {
    sign = true;
    packed_public_key[31] &= 0x7f;
  }
  public_key.y = from_rpr_le(packed_public_key);

  let mut y2 = public_key.y * public_key.y;
  let xa = 1-y2;
  let xb = bjj_a - (bjj_d * y2);
  let x2 = xa / xb;
  public_key.x = ec::sqrt(x2);

  let pm1d2 = -1 / 2;
  let sign2 = (BigUint56::from_bytes(public_key.x.to_le_bytes(32))
      .gt(BigUint56::from_bytes(pm1d2.to_le_bytes(32))));

  if(sign!=sign2) {
     public_key.x = -public_key.x;
  } 
  let bjj_affine = get_affine_curve();
  assert(bjj_affine.contains(public_key)); // checks the public key is valid

 let base_pt = get_base_point();
 let C1: Gaffine = bjj_affine.mul(randomness, base_pt);
 let plain_embedded: Gaffine = bjj_affine.mul(plaintext as Field, base_pt);
 let shared_secret: Gaffine = bjj_affine.mul(randomness, public_key);
 let C2: Gaffine = bjj_affine.add(shared_secret, plain_embedded);
 (C1,C2)
}

// translated from here: https://github.com/iden3/ffjavascript/blob/d1cd4ae32170aedd000865f0828b78a15df6f06f/src/scalar.js#L215
// and inspired by this: https://gist.github.com/signorecello/dad41f8b90ae48c7355bfd1f34f8885b
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
    let private_key: Field = 2291123624948246627368989940774052753470489062495018070576418670157516550852; // chosen randomly between 0 and l, the order of the prime subgroup of bjj
    let randomness: Field = 410498812303264265898947717948728411574828655879831784037118824925397244429; // chosen randomly between 0 and l, the order of the prime subgroup of bjj

    let mut public_key: Gaffine = priv_to_pub_key(private_key);
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
  let private_key = 2291123624948246627368989940774052753470489062495018070576418670157516550852;
  let pub_key: Gaffine = priv_to_pub_key(private_key);
  let packed_pub_key = [0xdc, 0x9f, 0x9f, 0xdb, 0x74, 0x6d, 0x0f, 0x07, 0xb0, 0x04, 0xcc, 0x43, 0x16, 0xe3, 0x49, 0x5a, 0x58, 0x57, 0x0b, 0x90, 0x66, 0x14, 0x99, 0xf8, 0xa6, 0xa6, 0x69, 0x6f, 0xf4, 0x15, 0x6b, 0xaa];//generated via circomlibjs
  let computed_packed_key = pack_point(pub_key);
  assert(computed_packed_key == packed_pub_key);

  let private_key2 = 1738143062869349530774161277267438032429985865461074036301785158041314559336;
  let pub_key2: Gaffine = priv_to_pub_key(private_key2);
  let packed_pub_key2 = [0x0c, 0x07, 0x99, 0x9c, 0x15, 0xd4, 0x06, 0xbc, 0x08, 0xd7, 0xf3, 0xf3, 0x1f, 0x62, 0xce, 0xdb, 0xc8, 0x9e, 0xbf, 0x3a, 0x53, 0xff, 0x4d, 0x3b, 0xf7, 0xe2, 0xd0, 0xdd, 0xa9, 0x31, 0x49, 0x04];//generated via circomlibjs
  let computed_packed_key2 = pack_point(pub_key2);
  assert(computed_packed_key2 == packed_pub_key2);

  let private_key3 = 1419151567905980068034978534653302182055502024582880680950402756828741268466;
  let pub_key3: Gaffine = priv_to_pub_key(private_key3);
  let packed_pub_key3 = [0x29, 0x48, 0x3d, 0xe5, 0xe8, 0x1d, 0xe9, 0x89, 0x3b, 0x56, 0x58, 0xd6, 0x05, 0x01, 0xa4, 0x56, 0x19, 0x8f, 0xd4, 0xbb, 0x39, 0xe4, 0x91, 0x6c, 0x2e, 0x30, 0xf2, 0x42, 0x23, 0xdf, 0xf0, 0xa6];//generated via circomlibjs
  let computed_packed_key3 = pack_point(pub_key3);
  assert(computed_packed_key3 == packed_pub_key3);
}

#[test]
fn test_unpack_point() {
  let private_keys: [Field] = [0x01e5cc52b94418c1d361a3479870df1f46fc4b3e697153843505053dd8b092da,0x05f53084112e74844b82f7cffe0ca07230681243ec3c77d53a6f31f5b04f7c4a,0x035599da748c880852fa5a5cfa417971e6212a7dcc5c2556fd274a775f0ddba6,
    0x04edd04fa218f3b0f32e109696a00baeb5f5b5bc6082b9dd53ff1ad1efe48f29,0x00edd199d52b82a65e7aaf6951f792462a84680022e139d8acf1c07d5168a827,0x01975e987782456b7e73a34835934b6a20c196f750bc7390c0f7d8303b469f7e,
    0x0143217d5df8e46eeac3b349b52903c8683cf72dee634c2fc22c63f8c32eb403,0x0146f1e7c7f39156351b16672223dd452d97fa92e603ce54bef4ea070f6714e8,0x0392f188c95d6ba5d6cceece1c88222b81b7ebfe33ebfe6a41d77d9cc68e7365,
    0x00f4a4b9474943d9d5642264055b4e20cccca5d72c9d51905083842a4c5b0634,0x056ff323dae95ce2e9d36cd98c478f408898361b9295440204c0269e85dd5857,0x0605286e2139a2b510c16127ee24fa8667ce749386c494e9e9c44107c26944dc,
    0x0232f1e3b4eef17264422b75959d18f9c740bce6ee38e501889f5058d158dc07,0x00ad6cb4f089e263a412160b1232b4893f6c3c1380384d70d4059d84b9ce3d78,0x000e71e555fa42fa642612664863c9aa30f23648208064aa509bf4925b2db59c];
  for private_key in private_keys {
    let public_key: Gaffine = priv_to_pub_key(private_key);
    let packed_pub_key = pack_point(public_key);
    let point = unpack_point(packed_pub_key);
    assert((point.x == public_key.x) & (point.y == public_key.y)); // check that unpack_point(packed_pub_key) always returns the original public key
    }
}

#[test]
fn test_pack_unpack(){
let private_key: Field = 196383954322680360577828551168351253384582625827285508038195147154523468362;
  let pub_key: Gaffine = priv_to_pub_key(private_key);

  let packed = pack_point(pub_key);
  let unpacked = unpack_point(packed);

  assert(unpacked.x==pub_key.x);
  assert(unpacked.y==pub_key.y);
}

#[test]
fn test_encrypt(){
  let x: u40 = 5;
  let bjj_affine = get_affine_curve();
  let base_pt = get_base_point();
  let embedded_x = bjj_affine.mul(x as Field, base_pt);

  let private_key = 196383954322680360577828551168351253384582625827285508038195147154523468362;
  let pub_key: Gaffine = priv_to_pub_key(private_key);

  let encrypted_point = exp_elgamal_encrypt(pub_key, x, 1);
  let decrypted_point = exp_elgamal_decrypt(private_key, encrypted_point);

  assert(decrypted_point.x == embedded_x.x);
  assert(decrypted_point.y == embedded_x.y);

  let packed = pack_point(pub_key);
  let unpacked = unpack_point(packed);

  let encrypted_with_unpacked = exp_elgamal_encrypt(unpacked, x, 1);
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

  let private_key = 196383954322680360577828551168351253384582625827285508038195147154523468362;
  let pub_key: Gaffine = priv_to_pub_key(private_key);

  let packed = pack_point(pub_key);


  let encrypted_with_packed = exp_elgamal_encrypt_packed(packed, x, 1);
  let decrypted_with_packed = exp_elgamal_decrypt(private_key, encrypted_with_packed);

  assert(decrypted_with_packed.x == embedded_x.x);
  assert(decrypted_with_packed.y == embedded_x.y);
}