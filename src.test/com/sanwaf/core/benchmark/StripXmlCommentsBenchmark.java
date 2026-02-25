package com.sanwaf.core.benchmark;

import java.util.regex.Pattern;

import org.junit.Test;

/**
 * Benchmark comparing approaches for stripping XML comments:
 * 1. Current — two String.replaceAll() calls (compiles regex each call)
 * 2. Precompiled Pattern — static final Pattern for both regexes
 * 3. indexOf loop — single-pass scan for <!-- and --> markers
 */
public class StripXmlCommentsBenchmark {

  // --- Precompiled patterns for approach 2 ---
  private static final Pattern P_SINGLE_LINE = Pattern.compile("<!--.*-->");
  private static final Pattern P_MULTI_LINE = Pattern.compile("<!--((?!<!--)[\\s\\S])*-->");

  private static final String TEST_INPUT_SINGLE_LINE =
      "<root>\n" +
      "  <!-- this is a comment -->\n" +
      "  <name>value</name>\n" +
      "  <!-- another comment -->\n" +
      "  <other>data</other>\n" +
      "</root>";

  private static final String TEST_INPUT_MULTI_LINE =
      "<root>\n" +
      "  <!--\n" +
      "    this is a\n" +
      "    multi-line comment\n" +
      "  -->\n" +
      "  <name>value</name>\n" +
      "  <!--\n" +
      "    another\n" +
      "    multi-line\n" +
      "  -->\n" +
      "  <other>data</other>\n" +
      "</root>";

  private static final String TEST_INPUT_MIXED =
      "<root>\n" +
      "  <!-- single line -->\n" +
      "  <name>value</name>\n" +
      "  <!--\n" +
      "    multi-line comment\n" +
      "  -->\n" +
      "  <other>data</other>\n" +
      "  <!-- another single line -->\n" +
      "  <last>item</last>\n" +
      "</root>";

  private static final String TEST_INPUT_NO_COMMENTS =
      "<root>\n" +
      "  <name>value</name>\n" +
      "  <other>data</other>\n" +
      "</root>";

  private static final int WARMUP_ITERS = 10_000;
  private static final int BENCH_ITERS  = 100_000;

  // --- Approach 1: Current (two replaceAll calls) ---
  private static String stripCurrent(String s) {
    if (s == null || s.isEmpty()) return "";
    return s.replaceAll("<!--.*-->", "").replaceAll("<!--((?!<!--)[\\s\\S])*-->", "");
  }

  // --- Approach 2: Precompiled Pattern ---
  private static String stripPrecompiled(String s) {
    if (s == null || s.isEmpty()) return "";
    s = P_SINGLE_LINE.matcher(s).replaceAll("");
    s = P_MULTI_LINE.matcher(s).replaceAll("");
    return s;
  }

  // --- Approach 3: indexOf loop ---
  private static String stripIndexOf(String s) {
    if (s == null || s.isEmpty()) return "";
    StringBuilder sb = new StringBuilder(s.length());
    int pos = 0;
    while (pos < s.length()) {
      int commentStart = s.indexOf("<!--", pos);
      if (commentStart < 0) {
        sb.append(s, pos, s.length());
        break;
      }
      sb.append(s, pos, commentStart);
      int commentEnd = s.indexOf("-->", commentStart + 4);
      if (commentEnd < 0) {
        // unclosed comment — keep the rest as-is
        sb.append(s, commentStart, s.length());
        break;
      }
      pos = commentEnd + 3;
    }
    return sb.toString();
  }

  @Test
  public void benchmarkStripXmlComments() {
    String[] inputs = { TEST_INPUT_SINGLE_LINE, TEST_INPUT_MULTI_LINE, TEST_INPUT_MIXED, TEST_INPUT_NO_COMMENTS };
    String[] labels = { "Single-line", "Multi-line", "Mixed", "No comments" };

    // Verify all approaches produce the same result
    for (int t = 0; t < inputs.length; t++) {
      String expected = stripCurrent(inputs[t]);
      String precompiled = stripPrecompiled(inputs[t]);
      String indexOf = stripIndexOf(inputs[t]);
      assert expected.equals(precompiled) : labels[t] + ": Precompiled result differs!";
      assert expected.equals(indexOf) : labels[t] + ": indexOf result differs!\nExpected: [" + expected + "]\nActual:   [" + indexOf + "]";
    }

    System.out.println("\n========== stripXmlComments Benchmark Results ==========");
    System.out.println("Iterations per scenario: " + BENCH_ITERS);

    for (int t = 0; t < inputs.length; t++) {
      String input = inputs[t];

      // Warmup
      for (int i = 0; i < WARMUP_ITERS; i++) {
        stripCurrent(input);
        stripPrecompiled(input);
        stripIndexOf(input);
      }

      // Benchmark 1: Current
      long start = System.nanoTime();
      for (int i = 0; i < BENCH_ITERS; i++) {
        stripCurrent(input);
      }
      long currentNs = System.nanoTime() - start;

      // Benchmark 2: Precompiled
      start = System.nanoTime();
      for (int i = 0; i < BENCH_ITERS; i++) {
        stripPrecompiled(input);
      }
      long precompiledNs = System.nanoTime() - start;

      // Benchmark 3: indexOf
      start = System.nanoTime();
      for (int i = 0; i < BENCH_ITERS; i++) {
        stripIndexOf(input);
      }
      long indexOfNs = System.nanoTime() - start;

      System.out.println("\n--- " + labels[t] + " ---");
      System.out.printf("  1. Current (replaceAll):  %,d ns total  |  %,d ns/op%n", currentNs, currentNs / BENCH_ITERS);
      System.out.printf("  2. Precompiled Pattern:   %,d ns total  |  %,d ns/op%n", precompiledNs, precompiledNs / BENCH_ITERS);
      System.out.printf("  3. indexOf loop:          %,d ns total  |  %,d ns/op%n", indexOfNs, indexOfNs / BENCH_ITERS);
      System.out.printf("  Precompiled is %.2fx faster than current%n", (double) currentNs / precompiledNs);
      System.out.printf("  indexOf is %.2fx faster than current%n", (double) currentNs / indexOfNs);
    }
    System.out.println("\n========================================================\n");
  }
}
