package com.sanwaf.core.benchmark;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Benchmark comparing Matcher allocation strategies for regex rule matching:
 * 1. New Matcher per call:          pattern.matcher(value).find()
 * 2. ThreadLocal cached Matcher:    cachedMatcher.get().reset(value).find()
 *
 * Simulates request validation where N parameter values are checked against
 * M regex rules (the hot path in ItemString / ItemRegex).
 */
@SuppressWarnings("ALL")
public class MatcherCacheBenchmark
{

  // Representative XSS/injection patterns from sanwaf's default ruleset
  private static final Pattern[] RULES = {
      Pattern.compile("(?:<|%3c)[^>]*(?:on\\w+\\s*=|style\\s*=)", Pattern.CASE_INSENSITIVE),
      Pattern.compile("(?:javascript|vbscript|data)\\s*:", Pattern.CASE_INSENSITIVE),
      Pattern.compile("<\\s*script[^>]*>", Pattern.CASE_INSENSITIVE),
      Pattern.compile("<\\s*iframe[^>]*>", Pattern.CASE_INSENSITIVE),
      Pattern.compile("(?:'|%27).*(?:--|#|%23)", Pattern.CASE_INSENSITIVE),
      Pattern.compile("(?:union\\s+select|insert\\s+into|delete\\s+from)", Pattern.CASE_INSENSITIVE),
      Pattern.compile("\\.\\.[\\\\/]", Pattern.CASE_INSENSITIVE),
      Pattern.compile("<\\s*(?:object|embed|applet|form|input|button|select|textarea)", Pattern.CASE_INSENSITIVE),
  };

  // Typical parameter values (clean — the common case in production)
  private static final String[] VALUES = {
      "John Doe",
      "john.doe@example.com",
      "123 Main Street, Apt 4B, Springfield IL 62704",
      "This is a normal comment with no special characters at all",
      "Product-SKU-12345-v2",
      "2025-06-15T14:30:00Z",
      "(555) 123-4567",
      "https://www.example.com/path?q=search+terms&page=1",
      "The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs.",
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore",
  };

  private static final int WARMUP_ITERS = 10_000;
  private static final int BENCH_ITERS = 100_000;

  // --- Approach 1: New Matcher per call (old code) ---
  private static int matchNewMatcher(Pattern[] rules, String[] values)
  {
    int found = 0;
    for (String value : values)
    {
      for (Pattern p : rules)
      {
        if (p.matcher(value).find())
        {
          found++;
        }
      }
    }
    return found;
  }

  // --- Approach 2: ThreadLocal cached Matcher (new code) ---
  private static final ThreadLocal<Matcher>[] CACHED_MATCHERS = new ThreadLocal[RULES.length];

  static
  {
    for (int i = 0; i < RULES.length; i++)
    {
      final int idx = i;
      CACHED_MATCHERS[i] = ThreadLocal.withInitial(() -> RULES[idx].matcher(""));
    }
  }

  private static int matchCachedMatcher(ThreadLocal<Matcher>[] cached, String[] values)
  {
    int found = 0;
    for (String value : values)
    {
      for (ThreadLocal<Matcher> tl : cached)
      {
        if (tl.get().reset(value).find())
        {
          found++;
        }
      }
    }
    return found;
  }

  // --- Allocation-focused: simple pattern to isolate matcher creation cost ---
  private static final Pattern SIMPLE = Pattern.compile("[a-z]+", Pattern.CASE_INSENSITIVE);
  private static final ThreadLocal<Matcher> SIMPLE_CACHED = ThreadLocal.withInitial(() -> SIMPLE.matcher(""));
  private static final String SIMPLE_VALUE = "HelloWorld";
  private static final int ALLOC_ITERS = 1_000_000;

  public static void main(String[] args)
  {
    MatcherCacheBenchmark bench = new MatcherCacheBenchmark();
    bench.benchmarkMatcherCache();
    bench.benchmarkAllocationOnly();
  }

  public void benchmarkMatcherCache()
  {
    // Verify both approaches produce the same result
    int expected = matchNewMatcher(RULES, VALUES);
    int cachedResult = matchCachedMatcher(CACHED_MATCHERS, VALUES);
    assert expected == cachedResult : "Results differ! new=" + expected + " cached=" + cachedResult;

    int checksPerIter = RULES.length * VALUES.length;

    // Warmup
    for (int i = 0; i < WARMUP_ITERS; i++)
    {
      matchNewMatcher(RULES, VALUES);
      matchCachedMatcher(CACHED_MATCHERS, VALUES);
    }

    // Benchmark 1: New Matcher per call
    long start = System.nanoTime();
    for (int i = 0; i < BENCH_ITERS; i++)
    {
      matchNewMatcher(RULES, VALUES);
    }
    long newNs = System.nanoTime() - start;

    // Benchmark 2: ThreadLocal cached Matcher
    start = System.nanoTime();
    for (int i = 0; i < BENCH_ITERS; i++)
    {
      matchCachedMatcher(CACHED_MATCHERS, VALUES);
    }
    long cachedNs = System.nanoTime() - start;

    // Print results
    long totalChecks = (long) BENCH_ITERS * checksPerIter;
    System.out.println("\n========== Matcher Cache Benchmark Results ==========");
    System.out.println("Rules: " + RULES.length + "  |  Values: " + VALUES.length + "  |  Checks/iter: " + checksPerIter);
    System.out.println("Iterations: " + BENCH_ITERS + "  |  Total find() calls: " + String.format("%,d", totalChecks));
    System.out.printf("1. New Matcher per call:       %,d ns total  |  %,d ns/op%n", newNs, newNs / totalChecks);
    System.out.printf("2. ThreadLocal cached Matcher:  %,d ns total  |  %,d ns/op%n", cachedNs, cachedNs / totalChecks);
    System.out.println("=====================================================");
    System.out.printf("ThreadLocal cached Matcher is %.2fx faster than new Matcher%n", (double) newNs / cachedNs);
    System.out.println("=====================================================\n");
  }

  public void benchmarkAllocationOnly()
  {
    // Warmup
    for (int i = 0; i < WARMUP_ITERS; i++)
    {
      SIMPLE.matcher(SIMPLE_VALUE).find();
      SIMPLE_CACHED.get().reset(SIMPLE_VALUE).find();
    }

    // Benchmark 1: New Matcher each time
    long start = System.nanoTime();
    for (int i = 0; i < ALLOC_ITERS; i++)
    {
      SIMPLE.matcher(SIMPLE_VALUE).find();
    }
    long newNs = System.nanoTime() - start;

    // Benchmark 2: Reuse via reset()
    start = System.nanoTime();
    for (int i = 0; i < ALLOC_ITERS; i++)
    {
      SIMPLE_CACHED.get().reset(SIMPLE_VALUE).find();
    }
    long cachedNs = System.nanoTime() - start;

    System.out.println("========== Allocation-Only Benchmark ==========");
    System.out.println("Pattern: " + SIMPLE.pattern() + "  |  Value: \"" + SIMPLE_VALUE + "\"");
    System.out.println("Iterations: " + String.format("%,d", ALLOC_ITERS));
    System.out.printf("1. pattern.matcher(value):           %,d ns total  |  %,d ns/op%n", newNs, newNs / ALLOC_ITERS);
    System.out.printf("2. cachedMatcher.get().reset(value): %,d ns total  |  %,d ns/op%n", cachedNs, cachedNs / ALLOC_ITERS);
    System.out.println("================================================");
    System.out.printf("ThreadLocal reset() is %.2fx faster than new Matcher%n", (double) newNs / cachedNs);
    System.out.println("================================================\n");
  }
}
