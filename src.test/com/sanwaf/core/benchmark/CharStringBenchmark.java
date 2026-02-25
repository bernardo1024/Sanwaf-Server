package com.sanwaf.core.benchmark;

/**
 * Benchmark comparing 2 approaches for extracting a single-character String:
 * 1. Current (before): key.substring(0, 1) — allocates a new String each call
 * 2. Cached charString(): lookup in a pre-built String[128] array — zero allocation for ASCII
 *
 * Tests both the hot-path scenario (getFromIndex: first char of a key used for
 * HashMap lookup) and a simulated map-get to measure end-to-end impact.
 */
@SuppressWarnings("ALL")
public class CharStringBenchmark {

  // --- Cached array (the new approach) ---
  private static final String[] CHAR_STRINGS = new String[128];
  static {
    for (int i = 0; i < 128; i++) {
      CHAR_STRINGS[i] = String.valueOf((char) i);
    }
  }

  private static String charString(char c) {
    return c < 128 ? CHAR_STRINGS[c] : String.valueOf(c);
  }

  // --- Test data ---
  private static final String[] KEYS = {
      "username", "password", "email", "firstName", "lastName",
      "address", "city", "state", "zip", "phone",
      "company", "title", "department", "role", "token",
      "sessionId", "csrfToken", "rememberMe", "locale", "timezone",
      "x-forwarded-for", "content-type", "authorization", "accept", "cookie",
  };

  private static final int WARMUP_ITERS = 50_000;
  private static final int BENCH_ITERS = 1_000_000;

  // --- Approach 1: substring (old) ---
  private static String substringApproach(String key) {
    return key.substring(0, 1);
  }

  // --- Approach 2: charString (new) ---
  private static String charStringApproach(String key) {
    return charString(key.charAt(0));
  }

  public static void main(String[] args) {
    new CharStringBenchmark().benchmarkCharString();
  }

  public void benchmarkCharString() {
    // Verify both approaches produce the same result
    for (String key : KEYS) {
      String a = substringApproach(key);
      String b = charStringApproach(key);
      assert a.equals(b) : "Results differ for key: " + key;
    }

    int keyCount = KEYS.length;

    // Warmup
    for (int i = 0; i < WARMUP_ITERS; i++) {
      substringApproach(KEYS[i % keyCount]);
      charStringApproach(KEYS[i % keyCount]);
    }

    // Benchmark 1: substring(0, 1)
    long start = System.nanoTime();
    for (int i = 0; i < BENCH_ITERS; i++) {
      substringApproach(KEYS[i % keyCount]);
    }
    long substringNs = System.nanoTime() - start;

    // Benchmark 2: charString()
    start = System.nanoTime();
    for (int i = 0; i < BENCH_ITERS; i++) {
      charStringApproach(KEYS[i % keyCount]);
    }
    long charStringNs = System.nanoTime() - start;

    // Print results
    System.out.println("\n========== charString vs substring Benchmark ==========");
    System.out.println("Iterations: " + BENCH_ITERS);
    System.out.printf("1. substring(0,1):   %,d ns total  |  %,d ns/op%n", substringNs, substringNs / BENCH_ITERS);
    System.out.printf("2. charString():     %,d ns total  |  %,d ns/op%n", charStringNs, charStringNs / BENCH_ITERS);
    System.out.println("========================================================");
    System.out.printf("charString() is %.2fx faster than substring(0,1)%n", (double) substringNs / charStringNs);
    System.out.println("========================================================\n");
  }
}
