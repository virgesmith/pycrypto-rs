# Python-rust binding with pyo3 and maturin

This replicates the functionality of the command-line crypto-rs module as a python module.

## Prerequisites

It uses the maturin and py03 crates for creating rust-implemented python modules.

Firstly, you need a working rust installation, and the [crypto-rs](https://github.com/virgesmith/crypto-rs) repo installed alongside this one (i.e. both have same parent directory).

Then install the python dependencies (virtualenv recommended):

```bash
pip install -r requirements.txt
```

Build locally:

```bash
maturin develop
```

Test:

```bash
pytest.py
```

## References

[py03 docs](https://docs.rs/pyo3/0.13.0/pyo3/index.html)

[py03 repo with examples](https://github.com/PyO3/pyo3)

[maturin docs](https://docs.rs/maturin/0.8.3/maturin/)