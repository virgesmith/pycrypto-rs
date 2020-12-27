// python entry points

use crate::crypto::*;

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
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

#[pyfunction]
fn hash160_py(filename: String) -> PyResult<String> {
  wrap_result(hash(filename, hash::hash160))
}

#[pyfunction]
fn hash256_py(filename: String) -> PyResult<String> {
  wrap_result(hash(filename, hash::hash256))
}

#[pyfunction]
fn pubkey_py(filename: String) -> PyResult<HashMap<String, String>> {
  wrap_result(pubkey(filename))
}

#[pyfunction]
fn prvkey_py(filename: String) -> PyResult<HashMap<String, String>> {
  wrap_result(prvkey(filename))
}

#[pyfunction]
fn sign_py(key_filename: String, msg_filename: String) -> PyResult<HashMap<String, String>> {
  wrap_result(sign(key_filename, msg_filename))
}


#[pyfunction]
fn verify_py(msg_filename: String, pubkey_hex: String, sig_hex: String) -> PyResult<bool> {
  wrap_result(verify(msg_filename, pubkey_hex, sig_hex))
}

#[pyfunction]
fn vanity_py(s: String, nth: usize) -> PyResult<HashMap<String, String>> {
  // Use u8 to ensure threads <= 256, defaulting to 1
  if nth < 1 || nth > 256 {
    return Err(PyValueError::new_err(format!("invalid number of threads requested {} (must be 1-256)", nth)));
  }

  wrap_result(vanity(s, nth))
}


#[pymodule]
fn pycrypto(_: Python, m: &PyModule) -> PyResult<()> {
  m.add_wrapped(wrap_pyfunction!(hash160_py))?;
  m.add_wrapped(wrap_pyfunction!(hash256_py))?;
  m.add_wrapped(wrap_pyfunction!(pubkey_py))?;
  m.add_wrapped(wrap_pyfunction!(prvkey_py))?;
  m.add_wrapped(wrap_pyfunction!(sign_py))?;
  m.add_wrapped(wrap_pyfunction!(verify_py))?;
  m.add_wrapped(wrap_pyfunction!(vanity_py))?;

  Ok(())
}

