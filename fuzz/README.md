# Fuzzing

Fuzz targets for [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (needs a nightly
toolchain):

```sh
cargo install cargo-fuzz
scripts/fuzz-seed.sh                       # seed corpora from test-vectors/
cargo +nightly fuzz run package -- -max_total_time=300
```

| Target | Checks |
|---|---|
| `manifest` | `Manifest::parse` never panics; parsed manifests round-trip |
| `sig_doc` | `SigDoc::parse` never panics; parsed documents round-trip |
| `index` | `Index::parse` and `Index::select` never panic; selections are newer and compatible |
| `path` | Accepted paths are relative, normalized and inside the payload roots |
| `package` | `verify`, `verify_head` and `inspect` never panic on any input |
| `extract` | `verify_and_extract` never writes outside the staging dir and cleans up on failure |

CI runs every target for a short time on each push to `main` and longer once a week. Crash
reproducers go in `fuzz/artifacts/` (not committed). Turn each crash into a regular test.
