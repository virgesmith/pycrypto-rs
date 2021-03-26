
use crypto_rs::hash;
use crypto_rs::key::{Key, PubKey};
use crypto_rs::address;
use crypto_rs::vanity;
use crypto_rs::CryptoResult;

use std::fs::File;
use std::io::Read;
use std::collections::HashMap;


pub fn hash(filename: String, func: impl Fn(&[u8]) -> Vec<u8>) -> CryptoResult<String> {

  let mut file = File::open(filename)?;
  let mut buffer = Vec::new();
  file.read_to_end(&mut buffer)?;

  Ok(hex::encode(func(&buffer)))
}

pub fn pubkey(filename: String) -> CryptoResult<HashMap<String, String>> {

  let key = Key::from_pem_file(&filename)?.to_pubkey()?;

  let mut m = HashMap::new();
  m.insert("uncompressed hex".to_string(), hex::encode(&key.public_key()?));
  m.insert("uncompressed base64".to_string(), base64::encode(&key.public_key()?));
  m.insert("uncompressed raw".to_string(), format!("{:?}", &key.public_key()?));
  m.insert("compressed hex".to_string(), hex::encode(&key.compressed_public_key()?));
  m.insert("compressed base64".to_string(), base64::encode(&key.compressed_public_key()?));
  m.insert("compressed raw".to_string(), format!("{:?}", &key.compressed_public_key()?));
  m.insert("BTC p2pkh".to_string(), address::p2pkh(&key.compressed_public_key()?));

  Ok(m)
}

pub fn prvkey(filename: String) -> CryptoResult<HashMap<String, String>> {

  let key = Key::from_pem_file(&filename)?;

  let mut m = HashMap::new();
  m.insert("hex".to_string(), hex::encode(&key.private_key()?));
  m.insert("base64".to_string(), base64::encode(&key.private_key()?));
  m.insert("raw".to_string(), format!("{:?}", &key.private_key()?));
  m.insert("BTC wif".to_string(), address::wif(&key.private_key()?));

  Ok(m)
}

pub fn sign(key_filename: String, msg_filename: String) -> CryptoResult<HashMap<String, String>> {

  let key = Key::from_pem_file(&key_filename)?;

  let mut file = File::open(&msg_filename)?;
  let mut buffer = Vec::new();
  file.read_to_end(&mut buffer)?;

  let hash = hash::hash256(&buffer);
  let sig = key.sign(&hash)?;

  let mut m = HashMap::new();
  m.insert("file".to_string(), msg_filename);
  m.insert("hash".to_string(), hex::encode(&hash));
  m.insert("signature".to_string(), hex::encode(&sig));

  Ok(m)
}

pub fn verify(msg_filename: String, pubkey_hex: String, sig_hex: String) -> CryptoResult<bool> {
  let mut file = File::open(msg_filename)?;

  let mut buffer = Vec::new();
  file.read_to_end(&mut buffer)?;

  let hash = hash::hash256(&buffer);

  let pubkey = PubKey::from_bytes(&hex::decode(pubkey_hex)?)?;

  let sig = hex::decode(&sig_hex)?;

  pubkey.verify(&hash, &sig)
}


pub fn vanity(s: String, nth: usize) -> CryptoResult<HashMap<String, String>> {

  //println!("finding key for BTC P2PKH address starting with 1{} using {} threads...", vanity, threads);

  let start = std::time::SystemTime::now();
  let (k, tries) = vanity::search(s, nth)?;

  let elapsed = start.elapsed().unwrap().as_millis() as f64 / 1000.0;
  //println!("{} attempts in {} seconds", total_tries, elapsed);

  let mut m = HashMap::new();
  m.insert("hex".to_string(), hex::encode(&k.private_key()?));
  m.insert("p2pkh".to_string(), address::p2pkh(&k.compressed_public_key()?));
  m.insert("wif".to_string(), address::wif(&k.private_key()?));
  m.insert("tries".to_string(), tries.to_string());
  m.insert("time(s)".to_string(), elapsed.to_string());

  Ok(m)
}
