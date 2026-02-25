package com.sanwaf.core.benchmark;

import java.util.regex.Pattern;

/**
 * Benchmark comparing approaches for removing whitespace around operators
 * in "related" expressions: )&&(, ||, :, ( , )
 *
 * 1. Current — five String.replaceAll() calls (compiles regex each call)
 * 2. Precompiled Pattern — static final Patterns for all five regexes
 * 3. Single-pass char[] scan — one traversal, no regex
 */
public class RemoveRelatedSpaceBenchmark {

  // --- Precompiled patterns for approach 2 ---
  private static final Pattern P_AND  = Pattern.compile("\\)\\s+&&\\s+\\(");
  private static final Pattern P_OR   = Pattern.compile("\\s+\\|\\|\\s+");
  private static final Pattern P_COL  = Pattern.compile("\\s+:\\s+");
  private static final Pattern P_OPEN = Pattern.compile("\\(\\s+");
  private static final Pattern P_CLOSE = Pattern.compile("\\s+\\)");

  // Realistic test inputs of varying complexity
  private static final String SIMPLE =
      "( fieldA ) && ( fieldB )";

  private static final String MEDIUM =
      "( fieldA : value1 ) && ( fieldB : value2 ) || ( fieldC : value3 )";

  private static final String COMPLEX =
      "( fieldA : value1 ) && ( fieldB : value2 ) || ( fieldC : value3 ) && " +
      "( fieldD : value4 ) || ( fieldE : value5 ) && ( fieldF ) || ( fieldG : value6 )";

  private static final String NO_SPACES =
      "(fieldA:value1)&&(fieldB:value2)||(fieldC:value3)";

  private static final int WARMUP_ITERS = 10_000;
  private static final int BENCH_ITERS  = 100_000;

  // --- Approach 1: Current (five replaceAll calls) ---
  private static String removeCurrent(String related) {
    related = related.trim();
    related = related.replaceAll("\\)\\s+&&\\s+\\(", ")&&(");
    related = related.replaceAll("\\s+\\|\\|\\s+", "||");
    related = related.replaceAll("\\s+:\\s+", ":");
    related = related.replaceAll("\\(\\s+", "(");
    related = related.replaceAll("\\s+\\)", ")");
    return related;
  }

  // --- Approach 2: Precompiled Pattern ---
  private static String removePrecompiled(String related) {
    related = related.trim();
    related = P_AND.matcher(related).replaceAll(")&&(");
    related = P_OR.matcher(related).replaceAll("||");
    related = P_COL.matcher(related).replaceAll(":");
    related = P_OPEN.matcher(related).replaceAll("(");
    related = P_CLOSE.matcher(related).replaceAll(")");
    return related;
  }

  // --- Approach 3: Single-pass char[] scan ---
  private static String removeSinglePass(String related) {
    related = related.trim();
    int len = related.length();
    if (len == 0) return related;
    char[] buf = new char[len];
    int out = 0;
    int i = 0;
    while (i < len) {
      char c = related.charAt(i);
      if (c == '(' && i + 1 < len && Character.isWhitespace(related.charAt(i + 1))) {
        // collapse "( " to "("
        buf[out++] = '(';
        do
          i++;
        while (i < len && Character.isWhitespace(related.charAt(i)));
      } else if (Character.isWhitespace(c)) {
        // look ahead: might be whitespace before ), ||, or :
        int wsStart = i;
        while (i < len && Character.isWhitespace(related.charAt(i))) i++;
        if (i < len && related.charAt(i) == ')') {
          // collapse " )" to ")"  — don't emit whitespace
        } else if (i + 1 < len && related.charAt(i) == '|' && related.charAt(i + 1) == '|') {
          // collapse " || " to "||"
          buf[out++] = '|';
          buf[out++] = '|';
          i += 2;
          while (i < len && Character.isWhitespace(related.charAt(i))) i++;
        } else if (i < len && related.charAt(i) == ':') {
          // collapse " : " to ":"
          buf[out++] = ':';
          do
            i++;
          while (i < len && Character.isWhitespace(related.charAt(i)));
        } else if (i < len && related.charAt(i) == '&' && i + 1 < len && related.charAt(i + 1) == '&') {
          // check if preceded by ) — look back in output buffer
          if (out > 0 && buf[out - 1] == ')') {
            buf[out++] = '&';
            buf[out++] = '&';
            i += 2;
            while (i < len && Character.isWhitespace(related.charAt(i))) i++;
            // if next char is '(' it will be handled normally
          } else {
            // not after ), emit the whitespace as-is
            for (int j = wsStart; j < i; j++) buf[out++] = related.charAt(j);
          }
        } else {
          // not a special context, keep the whitespace
          for (int j = wsStart; j < i; j++) buf[out++] = related.charAt(j);
        }
      } else {
        buf[out++] = c;
        i++;
      }
    }
    return new String(buf, 0, out);
  }
  
  public static void main(String[] args) {
    new RemoveRelatedSpaceBenchmark().benchmarkRemoveRelatedSpace();
  }

  public void benchmarkRemoveRelatedSpace() {
    String[] inputs = { SIMPLE, MEDIUM, COMPLEX, NO_SPACES };
    String[] labels = { "Simple", "Medium", "Complex", "No spaces" };

    // Verify all approaches produce the same result
    for (int t = 0; t < inputs.length; t++) {
      String expected = removeCurrent(inputs[t]);
      String precompiled = removePrecompiled(inputs[t]);
      String singlePass = removeSinglePass(inputs[t]);
      assert expected.equals(precompiled)
          : labels[t] + ": Precompiled differs!\nExpected: [" + expected + "]\nActual:   [" + precompiled + "]";
      assert expected.equals(singlePass)
          : labels[t] + ": Single-pass differs!\nExpected: [" + expected + "]\nActual:   [" + singlePass + "]";
    }

    System.out.println("\n========== removeRelatedSpace Benchmark Results ==========");
    System.out.println("Iterations per scenario: " + BENCH_ITERS);

    for (int t = 0; t < inputs.length; t++) {
      String input = inputs[t];

      // Warmup
      for (int i = 0; i < WARMUP_ITERS; i++) {
        removeCurrent(input);
        removePrecompiled(input);
        removeSinglePass(input);
      }

      // Benchmark 1: Current
      long start = System.nanoTime();
      for (int i = 0; i < BENCH_ITERS; i++) {
        removeCurrent(input);
      }
      long currentNs = System.nanoTime() - start;

      // Benchmark 2: Precompiled
      start = System.nanoTime();
      for (int i = 0; i < BENCH_ITERS; i++) {
        removePrecompiled(input);
      }
      long precompiledNs = System.nanoTime() - start;

      // Benchmark 3: Single-pass
      start = System.nanoTime();
      for (int i = 0; i < BENCH_ITERS; i++) {
        removeSinglePass(input);
      }
      long singlePassNs = System.nanoTime() - start;

      System.out.println("\n--- " + labels[t] + " ---");
      System.out.printf("  Input: \"%s\"%n", input);
      System.out.printf("  1. Current (replaceAll):  %,d ns total  |  %,d ns/op%n", currentNs, currentNs / BENCH_ITERS);
      System.out.printf("  2. Precompiled Pattern:   %,d ns total  |  %,d ns/op%n", precompiledNs, precompiledNs / BENCH_ITERS);
      System.out.printf("  3. Single-pass char[]:    %,d ns total  |  %,d ns/op%n", singlePassNs, singlePassNs / BENCH_ITERS);
      System.out.printf("  Precompiled is %.2fx faster than current%n", (double) currentNs / precompiledNs);
      System.out.printf("  Single-pass is %.2fx faster than current%n", (double) currentNs / singlePassNs);
    }
    System.out.println("\n==========================================================\n");
  }
}
