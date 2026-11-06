// 0003 T15 (historical): printed t15-zip-tokens.txt. Built as a scratch binary against
// polyjose (feature `deflate`) and aes-gcm =0.11.1; not part of the workspace.
// `bound64` and `empty` were encrypted on the OS CSPRNG, so a rerun gives other IVs;
// the forged tokens (fixed key and IV) and `key` are reproduced exactly.
use aes_gcm::aead::consts::U12;
use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit, Nonce};
use polyjose::jwa::{ContentEncAlg, KeyMgmtAlg};
use polyjose::jwe::{Encryptor, Recipient};
use polyjose::jwk::Jwk;
use polyjose::util::b64url_encode;

const KEY: [u8; 16] = [0x5A; 16];
const IV: [u8; 12] = [7; 12];

fn key() -> Jwk {
    Jwk::from_json(format!(r#"{{"kty":"oct","k":"{}"}}"#, b64url_encode(&KEY)).as_bytes()).unwrap()
}

fn compressed(pt: &[u8]) -> String {
    Encryptor::new(ContentEncAlg::A128GCM).compress()
        .recipient(Recipient::new(KeyMgmtAlg::Dir, &key()))
        .encrypt_compact(pt).unwrap()
}

fn forged(payload: &[u8]) -> String {
    let header = r#"{"alg":"dir","enc":"A128GCM","zip":"DEF"}"#;
    let aad = b64url_encode(header.as_bytes());
    let cipher = Aes128Gcm::new_from_slice(&KEY).unwrap();
    let nonce = Nonce::<U12>::try_from(&IV[..]).unwrap();
    let mut buf = payload.to_vec();
    let tag = cipher.encrypt_inout_detached(&nonce, aad.as_bytes(), buf.as_mut_slice().into()).unwrap();
    [aad, String::new(), b64url_encode(&IV), b64url_encode(&buf), b64url_encode(&tag)].join(".")
}

#[derive(Default)]
struct Bits { out: Vec<u8>, len: usize }
impl Bits {
    fn bit(&mut self, b: u32) { self.zeros(1); let l = self.len; *self.out.last_mut().unwrap() |= u8::from(b & 1 == 1) << ((l - 1) % 8); }
    fn value(&mut self, v: u32, n: u32) { (0..n).for_each(|i| self.bit(v >> i)); }
    fn code(&mut self, c: u32, n: u32) { (0..n).rev().for_each(|i| self.bit(c >> i)); }
    fn zeros(&mut self, n: usize) { self.len += n; self.out.resize(self.len.div_ceil(8), 0); }
}
fn bomb(matches: usize) -> Vec<u8> {
    let mut w = Bits::default();
    w.value(1, 1); w.value(0b10, 2); w.value(29, 5); w.value(0, 5); w.value(14, 4);
    for s in [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1] {
        w.value(match s { 18 => 1, 1 | 2 => 2, _ => 0 }, 3);
    }
    let z = |w: &mut Bits, n: u32| { w.code(0, 1); w.value(n - 11, 7); };
    z(&mut w, 97); w.code(0b11, 2); z(&mut w, 138); z(&mut w, 20); w.code(0b11, 2); z(&mut w, 28);
    w.code(0b10, 2); w.code(0b10, 2); w.code(0b10, 2); w.zeros(2 * matches); w.code(0b11, 2);
    w.out
}

fn main() {
    let pt64 = b"0123456789abcdef".repeat(4);
    println!("key {}", b64url_encode(&KEY));
    println!("bound64 {}", compressed(&pt64));
    println!("empty {}", compressed(b""));
    println!("reserved {}", forged(&[0x07]));
    println!("truncated {}", forged(&[0x03]));
    println!("nlen {}", forged(&[0x01, 0x05, 0x00, 0x00, 0x00]));
    println!("bomb {}", forged(&bomb(4000)));
}
