//! Regenerate the test vectors: `cargo run --example gen-vectors [-- <dir>]`
//! (default `test-vectors/`). See `test-vectors/README.md`.

mod vectors;

fn main() -> vectors::R<()> {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors").to_owned());
    let files = vectors::generate()?;
    vectors::write_all(std::path::Path::new(&dir), &files)?;
    println!("wrote {} files to {dir}", files.len());
    Ok(())
}
