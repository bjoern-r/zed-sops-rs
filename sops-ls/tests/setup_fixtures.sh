#!/usr/bin/env bash
# Creates an age key, a .sops.yaml and encrypted fixtures for tests/e2e.py.
set -euo pipefail
W=${1:?usage: setup_fixtures.sh <workdir>}
rm -rf "$W"; mkdir -p "$W/proj/secrets"; cd "$W"
age-keygen -o key.txt 2>/dev/null
export SOPS_AGE_KEY_FILE="$W/key.txt"
PUB=$(grep 'public key' key.txt | awk '{print $4}')
printf 'creation_rules:\n  - path_regex: secrets/.*\\.(yaml|json|env|ini)$\n    age: %s\n' "$PUB" > proj/.sops.yaml
cat > plain.yaml <<'Y'
# top comment
db:
  user: admin
  password: "s3cr3t pw"
  port: 5432
  enabled: true
list:
  - one
  - two
api_key_unencrypted: visible
Y
printf '{\n  "a": {"b": "x", "n": 3},\n  "arr": [1, "two"]\n}\n' > plain.json
printf '# db creds\nDB_USER=admin\nDB_PASS=multi word\nTOKEN_unencrypted=abc\n' > plain.env
printf '[db]\nuser = admin\npass = hunter2\n\n[api]\ntoken = xyz\n' > plain.ini
sops encrypt --age "$PUB" plain.yaml > proj/secrets/app.yaml
sops encrypt --age "$PUB" plain.json > app.enc.json
sops encrypt --age "$PUB" --input-type dotenv --output-type dotenv plain.env > app.enc.env
sops encrypt --age "$PUB" plain.ini > app.enc.ini
rm plain.*
