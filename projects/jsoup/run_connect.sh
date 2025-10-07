#!/usr/bin/env bash
set -euo pipefail

JAZZER="../jazzer/jazzer"
CP=".:jsoup.jar:../jazzer/jazzer_standalone.jar"
TARGET="harnesses.JsoupConnectFuzzer"
CORPUS_DIR="connect_corpus"
ARTIFACTS="artifacts_connect"

mkdir -p "$ARTIFACTS" "$CORPUS_DIR"

# Compile the fuzzer
javac -cp .:jsoup.jar harnesses/JsoupConnectFuzzer.java

echo "[run_connect] Starting Jazzer with target $TARGET and corpus $CORPUS_DIR"
  "$JAZZER" --cp="$CP" \
  --disabled_hooks=ServerSideRequestForgery \
  --target_class="$TARGET" \
  --reproducer_path="$ARTIFACTS" \
  -dict=connect_html.dict \
  "$CORPUS_DIR" || true

echo "[run_connect] Done. Crashes (if any) in $ARTIFACTS"
