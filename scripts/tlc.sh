#!/usr/bin/env bash
set -euo pipefail
if ! command -v java >/dev/null 2>&1; then
  echo "SKIP TLC: java not found"
  exit 0
fi
JAR="${TLA_TOOLS_JAR:-tla2tools.jar}"
if [ ! -f "$JAR" ]; then
  echo "SKIP TLC: set TLA_TOOLS_JAR or place tla2tools.jar in this directory"
  exit 0
fi
set +e
java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -config specs/VerifyBeforeLoadNaive.cfg specs/VerifyBeforeLoad.tla > specs/tlc-naive.out 2>&1
naive_status=$?
set -e
if [ "$naive_status" -eq 0 ]; then
  echo "Expected naive model to produce a counterexample"
  cat specs/tlc-naive.out
  exit 1
fi
grep -Eq "Invariant .* is violated|Error: Invariant" specs/tlc-naive.out
java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -config specs/VerifyBeforeLoadSafe.cfg specs/VerifyBeforeLoad.tla > specs/tlc-safe.out 2>&1
grep -q "No error has been found" specs/tlc-safe.out
echo "TLC naive counterexample and safe invariant verified"
