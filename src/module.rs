// python entry points

use crate::crypto::*;

use pyo3::prelude::*;
use pyo3::exceptions::{PyException, PyValueError};

use crypto_rs::CryptoResult;
use crypto_rs::hash;

use std::collections::HashMap;

// workaround for Error not converting to PyResult::Err
fn wrap_result<T>(res: CryptoResult<T>) -> PyResult<T> {
  match res {
    Ok(r) => Ok(r),
    // TODO to map errors to python exception types?
    Err(e) => Err(PyException::new_err(format!("{}", e)))
  }
}

#[pymodule]
fn crypto(_: Python, m: &PyModule) -> PyResult<()> {

  #[pyfn(m, "hash160")]
  fn hash160_py(filename: String) -> PyResult<String> {
    wrap_result(hash(filename, hash::hash160))
  }

  #[pyfn(m, "hash256")]
  fn hash256_py(filename: String) -> PyResult<String> {
    wrap_result(hash(filename, hash::hash256))
  }

  #[pyfn(m, "pubkey")]
  fn pubkey_py(filename: String) -> PyResult<HashMap<String, String>> {
    wrap_result(pubkey(filename))
  }

  #[pyfn(m, "prvkey")]
  fn prvkey_py(filename: String) -> PyResult<HashMap<String, String>> {
    wrap_result(prvkey(filename))
  }

  #[pyfn(m, "sign")]
  fn sign_py(key_filename: String, msg_filename: String) -> PyResult<HashMap<String, String>> {
    wrap_result(sign(key_filename, msg_filename))
  }

  #[pyfn(m, "verify")]
  fn verify_py(msg_filename: String, pubkey_hex: String, sig_hex: String) -> PyResult<bool> {
    wrap_result(verify(msg_filename, pubkey_hex, sig_hex))
  }

  #[pyfn(m, "vanity")]
  fn vanity_py(s: String, nth: usize) -> PyResult<HashMap<String, String>> {
    // Use u8 to ensure threads <= 256, defaulting to 1
    if !(1..=256).contains(&nth) {
      return Err(PyValueError::new_err(format!("invalid number of threads requested {} (must be 1-256)", nth)));
    }

    wrap_result(vanity(s, nth))
  }

  Ok(())
}

