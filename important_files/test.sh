#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
./build.sh
java -cp classes SelfTest
java -cp classes IntegrationTest
python3 tests/prover_reveal_smoke.py
python3 tests/full_protocol_smoke.py

python3 tests/auctioneer_mpc_smoke.py
python3 tests/six_party_smoke.py
