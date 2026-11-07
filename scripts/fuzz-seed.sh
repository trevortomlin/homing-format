#!/usr/bin/env bash
# Seed the fuzz corpora from the committed test vectors.
set -euo pipefail
cd "$(dirname "$0")/.."
tv=test-vectors
for t in package extract; do
  mkdir -p "fuzz/corpus/$t"
  cp "$tv"/packages/pass-*.homing "fuzz/corpus/$t/"
done
mkdir -p fuzz/corpus/index fuzz/corpus/sig_doc fuzz/corpus/manifest fuzz/corpus/path
cp "$tv"/indexes/*.json fuzz/corpus/index/
cp "$tv"/indexes/*.json.sig fuzz/corpus/sig_doc/
python3 -I - "$tv" fuzz/corpus/manifest <<'PY'
import sys, tarfile, io, pathlib
src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
for p in sorted((src / "packages").glob("pass-uncompressed.homing")) + sorted((src / "packages").glob("schema-*.homing")):
    with tarfile.open(p) as t:
        m = t.getmembers()[0]
        if m.name == "manifest.json" and m.size < 65536:
            (out / p.stem).write_bytes(t.extractfile(m).read())
PY
printf 'bundle/flutter_assets/a' > fuzz/corpus/path/a
printf 'config/app.json' > fuzz/corpus/path/b
echo "seeded fuzz/corpus/"
