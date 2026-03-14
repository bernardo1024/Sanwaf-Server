#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../../../../.."

# Parse --compare flag
COMPARE_BASELINE=""
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --compare)
      COMPARE_BASELINE="$2"
      shift 2
      ;;
    *)
      ARGS+=("$1")
      shift
      ;;
  esac
done

# If comparing, inject -o to a temp file unless user already specified -o
OUTPUT_FILE=""
if [ -n "$COMPARE_BASELINE" ]; then
  HAS_OUTPUT=false
  for arg in "${ARGS[@]}"; do
    if [ "$arg" = "-o" ]; then HAS_OUTPUT=true; break; fi
  done
  if ! $HAS_OUTPUT; then
    OUTPUT_FILE=$(mktemp /tmp/jmh-current-XXXXXX.json)
    ARGS+=("-o" "$OUTPUT_FILE")
  else
    # Find the file after -o
    for i in "${!ARGS[@]}"; do
      if [ "${ARGS[$i]}" = "-o" ]; then
        OUTPUT_FILE="${ARGS[$((i+1))]}"
        break
      fi
    done
  fi
fi

source .mvn/jdk.env
# Compile test sources (triggers JMH annotation processing)
mvn test-compile -q
# Build classpath and run
CP=$(mvn -q dependency:build-classpath \
  -DincludeScope=test -Dmdep.outputFile=/dev/stdout 2>/dev/null)
"$JAVA_HOME/bin/java" -cp "$CP:$(pwd)/target/classes:$(pwd)/target/test-classes" \
  com.sanwaf.core.benchmark.SanwafJmhBenchmark "${ARGS[@]}"

# Compare if requested
if [ -n "$COMPARE_BASELINE" ] && [ -n "$OUTPUT_FILE" ]; then
  echo ""
  echo "=== Benchmark Comparison ==="
  bash "$SCRIPT_DIR/compare-benchmarks.sh" "$COMPARE_BASELINE" "$OUTPUT_FILE"
fi
