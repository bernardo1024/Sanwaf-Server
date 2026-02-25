package com.sanwaf.core.benchmark;

import java.util.regex.Pattern;

/**
 * Benchmark comparing 4 approaches for escapeChars() replacements:
 * 1. Current: String.replaceAll() — compiles regex each call
 * 2. String.replace() — literal matching, no regex
 * 3. Precompiled Pattern — static final Pattern + matcher().replaceAll()
 * 4. Single-pass char[] scan — one traversal, no intermediate strings
 */
@SuppressWarnings("ALL")
public class EscapeCharsBenchmark
{

  // --- Precompiled patterns for approach 3 ---
  private static final Pattern P_HASH = Pattern.compile("\\\\#");
  private static final Pattern P_A = Pattern.compile("\\\\A");
  private static final Pattern P_a = Pattern.compile("\\\\a");
  private static final Pattern P_c = Pattern.compile("\\\\c");
  private static final Pattern P_LBRK = Pattern.compile("\\\\\\[");
  private static final Pattern P_RBRK = Pattern.compile("\\\\\\]");
  private static final Pattern P_PIPE = Pattern.compile("\\\\\\|");
  private static final Pattern P_x = Pattern.compile("\\\\x");
  private static final Pattern P_COLON = Pattern.compile("\\\\:");
  private static final Pattern P_EQ = Pattern.compile("\\\\=");
  private static final Pattern P_LPAR = Pattern.compile("\\\\\\(");
  private static final Pattern P_RPAR = Pattern.compile("\\\\\\)");
  private static final Pattern P_PLUS = Pattern.compile("\\\\\\+");
  private static final Pattern P_MINUS = Pattern.compile("\\\\\\-");
  private static final Pattern P_SEMI = Pattern.compile("\\\\;");

  private static final String TEST_INPUT =
      "field\\#name\\Aupper\\alower\\cctrl\\[left\\]right\\|pipe\\xhex\\:colon\\=eq\\(lp\\)rp\\+plus\\-minus\\;semi some normal text";

  private static final int WARMUP_ITERS = 10_000;
  private static final int BENCH_ITERS = 100_000;

  // --- Approach 1: Current (String.replaceAll) ---
  private static String escapeCharsCurrent(String s)
  {
    s = s.replaceAll("\\\\#", "\t");
    s = s.replaceAll("\\\\A", "\n");
    s = s.replaceAll("\\\\a", "\r");
    s = s.replaceAll("\\\\c", "\f");
    s = s.replaceAll("\\\\\\[", "\b");
    s = s.replaceAll("\\\\\\]", "\0");
    s = s.replaceAll("\\\\\\|", "\1");
    s = s.replaceAll("\\\\x", "\2");
    s = s.replaceAll("\\\\:", "\3");
    s = s.replaceAll("\\\\=", "\4");
    s = s.replaceAll("\\\\\\(", "\5");
    s = s.replaceAll("\\\\\\)", "\6");
    s = s.replaceAll("\\\\\\+", "\7");
    s = s.replaceAll("\\\\\\-", "\016");
    s = s.replaceAll("\\\\;", "\017");
    return s;
  }

  // --- Approach 2: String.replace (literal) ---
  private static String escapeCharsReplace(String s)
  {
    s = s.replace("\\#", "\t");
    s = s.replace("\\A", "\n");
    s = s.replace("\\a", "\r");
    s = s.replace("\\c", "\f");
    s = s.replace("\\[", "\b");
    s = s.replace("\\]", "\0");
    s = s.replace("\\|", "\1");
    s = s.replace("\\x", "\2");
    s = s.replace("\\:", "\3");
    s = s.replace("\\=", "\4");
    s = s.replace("\\(", "\5");
    s = s.replace("\\)", "\6");
    s = s.replace("\\+", "\7");
    s = s.replace("\\-", "\016");
    s = s.replace("\\;", "\017");
    return s;
  }

  // --- Approach 3: Precompiled Pattern ---
  private static String escapeCharsPrecompiled(String s)
  {
    s = P_HASH.matcher(s).replaceAll("\t");
    s = P_A.matcher(s).replaceAll("\n");
    s = P_a.matcher(s).replaceAll("\r");
    s = P_c.matcher(s).replaceAll("\f");
    s = P_LBRK.matcher(s).replaceAll("\b");
    s = P_RBRK.matcher(s).replaceAll("\0");
    s = P_PIPE.matcher(s).replaceAll("\1");
    s = P_x.matcher(s).replaceAll("\2");
    s = P_COLON.matcher(s).replaceAll("\3");
    s = P_EQ.matcher(s).replaceAll("\4");
    s = P_LPAR.matcher(s).replaceAll("\5");
    s = P_RPAR.matcher(s).replaceAll("\6");
    s = P_PLUS.matcher(s).replaceAll("\7");
    s = P_MINUS.matcher(s).replaceAll("\016");
    s = P_SEMI.matcher(s).replaceAll("\017");
    return s;
  }

  // --- Approach 4: Single-pass char[] scan ---
  private static String escapeCharsSinglePass(String s)
  {
    char[] src = s.toCharArray();
    char[] dst = new char[src.length];
    int d = 0;
    for (int i = 0; i < src.length; i++)
    {
      if (src[i] == '\\' && i + 1 < src.length)
      {
        char next = src[i + 1];
        char replacement;
        switch (next)
        {
        case '#':
          replacement = '\t';
          break;
        case 'A':
          replacement = '\n';
          break;
        case 'a':
          replacement = '\r';
          break;
        case 'c':
          replacement = '\f';
          break;
        case '[':
          replacement = '\b';
          break;
        case ']':
          replacement = '\0';
          break;
        case '|':
          replacement = '\1';
          break;
        case 'x':
          replacement = '\2';
          break;
        case ':':
          replacement = '\3';
          break;
        case '=':
          replacement = '\4';
          break;
        case '(':
          replacement = '\5';
          break;
        case ')':
          replacement = '\6';
          break;
        case '+':
          replacement = '\7';
          break;
        case '-':
          replacement = '\016';
          break;
        case ';':
          replacement = '\017';
          break;
        default:
          dst[d++] = src[i];
          continue;
        }
        dst[d++] = replacement;
        i++; // skip next char
      }
      else
      {
        dst[d++] = src[i];
      }
    }
    return new String(dst, 0, d);
  }

  public static void main(String[] args)
  {
    new EscapeCharsBenchmark().benchmarkEscapeChars();
  }

  public void benchmarkEscapeChars()
  {
    // Verify all 4 approaches produce the same result
    String expected = escapeCharsCurrent(TEST_INPUT);
    String replaceResult = escapeCharsReplace(TEST_INPUT);
    String precompiledResult = escapeCharsPrecompiled(TEST_INPUT);
    String singlePassResult = escapeCharsSinglePass(TEST_INPUT);

    assert expected.equals(replaceResult) : "String.replace() result differs!";
    assert expected.equals(precompiledResult) : "Precompiled result differs!";
    assert expected.equals(singlePassResult) : "Single-pass result differs!";

    // Warmup
    for (int i = 0; i < WARMUP_ITERS; i++)
    {
      escapeCharsCurrent(TEST_INPUT);
      escapeCharsReplace(TEST_INPUT);
      escapeCharsPrecompiled(TEST_INPUT);
      escapeCharsSinglePass(TEST_INPUT);
    }

    // Benchmark 1: Current (replaceAll)
    long start = System.nanoTime();
    for (int i = 0; i < BENCH_ITERS; i++)
    {
      escapeCharsCurrent(TEST_INPUT);
    }
    long currentNs = System.nanoTime() - start;

    // Benchmark 2: String.replace
    start = System.nanoTime();
    for (int i = 0; i < BENCH_ITERS; i++)
    {
      escapeCharsReplace(TEST_INPUT);
    }
    long replaceNs = System.nanoTime() - start;

    // Benchmark 3: Precompiled Pattern
    start = System.nanoTime();
    for (int i = 0; i < BENCH_ITERS; i++)
    {
      escapeCharsPrecompiled(TEST_INPUT);
    }
    long precompiledNs = System.nanoTime() - start;

    // Benchmark 4: Single-pass char[]
    start = System.nanoTime();
    for (int i = 0; i < BENCH_ITERS; i++)
    {
      escapeCharsSinglePass(TEST_INPUT);
    }
    long singlePassNs = System.nanoTime() - start;

    // Print results
    System.out.println("\n========== escapeChars Benchmark Results ==========");
    System.out.println("Iterations: " + BENCH_ITERS);
    System.out.printf("1. Current (replaceAll):    %,d ns total  |  %,d ns/op%n", currentNs, currentNs / BENCH_ITERS);
    System.out.printf("2. String.replace():        %,d ns total  |  %,d ns/op%n", replaceNs, replaceNs / BENCH_ITERS);
    System.out.printf("3. Precompiled Pattern:     %,d ns total  |  %,d ns/op%n", precompiledNs, precompiledNs / BENCH_ITERS);
    System.out.printf("4. Single-pass char[]:      %,d ns total  |  %,d ns/op%n", singlePassNs, singlePassNs / BENCH_ITERS);
    System.out.println("===================================================");
    System.out.printf("String.replace() is %.2fx faster than current%n", (double) currentNs / replaceNs);
    System.out.printf("Precompiled Pattern is %.2fx faster than current%n", (double) currentNs / precompiledNs);
    System.out.printf("Single-pass char[] is %.2fx faster than current%n", (double) currentNs / singlePassNs);
    System.out.println("===================================================\n");
  }
}
