#!/usr/bin/env bash
set -euo pipefail

JAZZER="../jazzer/jazzer"
CP=".:jsoup.jar:../jazzer/jazzer_standalone.jar"
TARGET="harnesses.JsoupConnectMockFuzzer"
CORPUS_DIR="mock_connect_corpus"
ARTIFACTS="artifacts_connect_mock"

mkdir -p "$ARTIFACTS" "$CORPUS_DIR"

# Compile the fuzzer
javac -cp .:jsoup.jar harnesses/JsoupConnectMockFuzzer.java

echo "[run_connect_mock] Starting Jazzer with target $TARGET and corpus $CORPUS_DIR"

  "$JAZZER" --cp="$CP" \
  --disabled_hooks=ServerSideRequestForgery \
  --target_class="$TARGET" \
  --reproducer_path="$ARTIFACTS" \
  "$CORPUS_DIR" || true

echo "[run_connect_mock] Done. Crashes (if any) in $ARTIFACTS"
