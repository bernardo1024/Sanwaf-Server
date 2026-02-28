package com.sanwaf.core.benchmark;

import com.sanwaf.core.Sanwaf;
import com.sanwaf.log.Logger;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.CommandLineOptions;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

/**
 * JMH benchmarks for all Sanwaf validation Item types.
 * <p>
 * Run all:    bash src.test/com/sanwaf/core/benchmark/run-benchmarks.sh
 * Run one:    bash run-benchmarks.sh -p ".*numericClean"
 * Compare:    bash run-benchmarks.sh --compare baseline.json
 * Save:       bash run-benchmarks.sh -o results.json
 * See:        bash run-benchmarks.sh --help
 */
@BenchmarkMode({Mode.Throughput, Mode.AverageTime})
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Thread)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 2, jvmArgsAppend = {"-Xms256m", "-Xmx256m"})
public class SanwafJmhBenchmark
{
  private Sanwaf sanwaf;

  // --- Test values ---
  private String cleanText;
  private String dirtyXss;
  private String cleanTextShort;
  private String cleanTextLong;
  private String cleanUrl;
  private String cleanHtmlEntities;
  private String dirtyXssEncoded;
  private String dirtyXssInText;
  private String dirtyXssLong;
  private String dirtyXssImg;
  private String cleanNumeric;
  private String dirtyNumeric;
  private String cleanInteger;
  private String dirtyInteger;
  private String cleanNumericDelimited;
  private String dirtyNumericDelimited;
  private String cleanIntegerDelimited;
  private String dirtyIntegerDelimited;
  private String cleanAlphanumeric;
  private String dirtyAlphanumeric;
  private String cleanAlphanumericMore;
  private String dirtyAlphanumericMore;
  private String cleanChar;
  private String dirtyChar;
  private String cleanConstant;
  private String dirtyConstant;
  private String cleanRegex;
  private String dirtyRegex;
  private String cleanInlineRegex;
  private String dirtyInlineRegex;
  private String cleanFormat;
  private String dirtyFormat;

  // --- Static API XML fragments ---
  private static final String NUMERIC_XML =
      "<item><name>n</name><type>n</type><max></max><min></min><msg></msg><uri></uri></item>";
  private static final String INTEGER_XML =
      "<item><name>i</name><type>i</type><max></max><min></min><msg></msg><uri></uri></item>";
  private static final String NUMERIC_DELIMITED_XML =
      "<item><name>nd</name><type>n{,}</type><max></max><min></min><msg></msg><uri></uri></item>";
  private static final String INTEGER_DELIMITED_XML =
      "<item><name>id</name><type>i{,}</type><max></max><min></min><msg></msg><uri></uri></item>";
  private static final String ALPHANUMERIC_XML =
      "<item><name>a</name><type>a</type><max></max><min></min><msg></msg><uri></uri></item>";
  private static final String AN_MORE_XML =
      "<item><name>am</name><type>a{?\\s:}</type><max></max><min></min><msg></msg><uri></uri></item>";
  private static final String CHAR_XML =
      "<item><name>c</name><type>c</type><max></max><min></min><msg></msg><uri></uri></item>";
  private static final String CONSTANT_XML =
      "<item><name>k</name><type>k{FOO,BAR,FAR}</type><max></max><min></min><msg></msg><uri></uri></item>";
  private static final String REGEX_XML =
      "<item><name>r</name><type>r{telephone}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>";
  private static final String INLINE_REGEX_XML =
      "<item><name>x</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type>"
      + "<max>12</max><min>12</min><msg></msg><uri></uri></item>";
  private static final String FORMAT_XML =
      "<item><name>f</name><type>f{###-###-####}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>";

  @Setup(Level.Trial)
  public void setUp() throws IOException
  {
    Logger noOpLogger = new Logger()
    {
      public void error(String s) {}
      public void warn(String s) {}
      public void info(String s) {}
      public boolean isErrorEnabled() { return false; }
      public boolean isWarnEnabled() { return false; }
      public boolean isInfoEnabled() { return false; }
    };
    sanwaf = new Sanwaf(noOpLogger, "/sanwaf-isThreat.xml");

    // String (instance API — runs all shield regex patterns)
    cleanText = "This is a perfectly normal string with no threats";
    dirtyXss = "<script>alert(1)</script>";

    // Short clean string — regex still runs (regexMinLen=0 in config)
    cleanTextShort = "ok";

    // Long clean text — realistic textarea/comment body (~300 chars)
    cleanTextLong = "Thank you for your prompt response regarding our order. "
        + "We would like to confirm that the delivery address is 123 Main Street, "
        + "Suite 400, Springfield IL 62701. Please ensure the package is marked fragile "
        + "as it contains sensitive electronic equipment. Our reference number is PO-2024-78543. "
        + "Contact us at support if there are any issues with fulfillment.";

    // URL with special chars — no angle brackets
    cleanUrl = "https://example.com/search?q=test+query&page=2&sort=desc";

    // Contains < and > as text, not tags — tests regex backtracking
    cleanHtmlEntities = "Price: $5 — 50% off &amp; free shipping! Use code <SAVE20>";

    // URL-encoded XSS — tests encoded branch of regex
    dirtyXssEncoded = "%3cscript%3ealert(1)%3c/script%3e";

    // XSS buried at end of clean text — measures scan cost before match
    dirtyXssInText = "Please review this document for issues <script>alert(1)</script>";

    // Long clean text + XSS at end — worst case scan
    dirtyXssLong = cleanTextLong + " <img src=x>";

    // Different tag type, single tag
    dirtyXssImg = "<img src=x onerror=alert(1)>";

    // Numeric
    cleanNumeric = "-123.456";
    dirtyNumeric = "abc123";

    // Integer
    cleanInteger = "12345";
    dirtyInteger = "123.45";

    // Numeric delimited
    cleanNumericDelimited = "-123.456,789";
    dirtyNumericDelimited = "abc,123";

    // Integer delimited
    cleanIntegerDelimited = "1,2,3,4,5";
    dirtyIntegerDelimited = "1,2.5,3";

    // Alphanumeric
    cleanAlphanumeric = "abc123";
    dirtyAlphanumeric = "abc123!!!";

    // Alphanumeric and more
    cleanAlphanumericMore = "abc  123";
    dirtyAlphanumericMore = "abc123!!!";

    // Char
    cleanChar = "a";
    dirtyChar = "abc";

    // Constant
    cleanConstant = "FOO";
    dirtyConstant = "INVALID";

    // Regex (named pattern — telephone)
    cleanRegex = "555-555-5555";
    dirtyRegex = "notAPhone!!!";

    // Inline regex
    cleanInlineRegex = "123.123.1234";
    dirtyInlineRegex = "notAPhone";

    // Format
    cleanFormat = "555-555-5555";
    dirtyFormat = "notAPhone!!!";

    // Prime static item caches so benchmarks measure steady-state
    Sanwaf.isThreat(cleanNumeric, NUMERIC_XML);
    Sanwaf.isThreat(cleanInteger, INTEGER_XML);
    Sanwaf.isThreat(cleanNumericDelimited, NUMERIC_DELIMITED_XML);
    Sanwaf.isThreat(cleanIntegerDelimited, INTEGER_DELIMITED_XML);
    Sanwaf.isThreat(cleanAlphanumeric, ALPHANUMERIC_XML);
    Sanwaf.isThreat(cleanAlphanumericMore, AN_MORE_XML);
    Sanwaf.isThreat(cleanChar, CHAR_XML);
    Sanwaf.isThreat(cleanConstant, CONSTANT_XML);
    Sanwaf.isThreat(cleanRegex, REGEX_XML);
    Sanwaf.isThreat(cleanInlineRegex, INLINE_REGEX_XML);
    Sanwaf.isThreat(cleanFormat, FORMAT_XML);
  }

  // ==================== String (instance API — full pipeline) ====================

  @Benchmark
  public boolean stringClean()
  {
    return sanwaf.isThreat(cleanText);
  }

  @Benchmark
  public boolean stringDirtyXss()
  {
    return sanwaf.isThreat(dirtyXss);
  }

  @Benchmark
  public boolean stringCleanShort() { return sanwaf.isThreat(cleanTextShort); }

  @Benchmark
  public boolean stringCleanLong() { return sanwaf.isThreat(cleanTextLong); }

  @Benchmark
  public boolean stringCleanUrl() { return sanwaf.isThreat(cleanUrl); }

  @Benchmark
  public boolean stringCleanHtmlEntities() { return sanwaf.isThreat(cleanHtmlEntities); }

  @Benchmark
  public boolean stringDirtyXssEncoded() { return sanwaf.isThreat(dirtyXssEncoded); }

  @Benchmark
  public boolean stringDirtyXssInText() { return sanwaf.isThreat(dirtyXssInText); }

  @Benchmark
  public boolean stringDirtyXssLong() { return sanwaf.isThreat(dirtyXssLong); }

  @Benchmark
  public boolean stringDirtyXssImg() { return sanwaf.isThreat(dirtyXssImg); }

  // ==================== Numeric ====================

  @Benchmark
  public boolean numericClean()
  {
    return Sanwaf.isThreat(cleanNumeric, NUMERIC_XML);
  }

  @Benchmark
  public boolean numericDirty()
  {
    return Sanwaf.isThreat(dirtyNumeric, NUMERIC_XML);
  }

  // ==================== Integer ====================

  @Benchmark
  public boolean integerClean()
  {
    return Sanwaf.isThreat(cleanInteger, INTEGER_XML);
  }

  @Benchmark
  public boolean integerDirty()
  {
    return Sanwaf.isThreat(dirtyInteger, INTEGER_XML);
  }

  // ==================== Numeric Delimited ====================

  @Benchmark
  public boolean numericDelimitedClean()
  {
    return Sanwaf.isThreat(cleanNumericDelimited, NUMERIC_DELIMITED_XML);
  }

  @Benchmark
  public boolean numericDelimitedDirty()
  {
    return Sanwaf.isThreat(dirtyNumericDelimited, NUMERIC_DELIMITED_XML);
  }

  // ==================== Integer Delimited ====================

  @Benchmark
  public boolean integerDelimitedClean()
  {
    return Sanwaf.isThreat(cleanIntegerDelimited, INTEGER_DELIMITED_XML);
  }

  @Benchmark
  public boolean integerDelimitedDirty()
  {
    return Sanwaf.isThreat(dirtyIntegerDelimited, INTEGER_DELIMITED_XML);
  }

  // ==================== Alphanumeric ====================

  @Benchmark
  public boolean alphanumericClean()
  {
    return Sanwaf.isThreat(cleanAlphanumeric, ALPHANUMERIC_XML);
  }

  @Benchmark
  public boolean alphanumericDirty()
  {
    return Sanwaf.isThreat(dirtyAlphanumeric, ALPHANUMERIC_XML);
  }

  // ==================== Alphanumeric And More ====================

  @Benchmark
  public boolean alphanumericMoreClean()
  {
    return Sanwaf.isThreat(cleanAlphanumericMore, AN_MORE_XML);
  }

  @Benchmark
  public boolean alphanumericMoreDirty()
  {
    return Sanwaf.isThreat(dirtyAlphanumericMore, AN_MORE_XML);
  }

  // ==================== Char ====================

  @Benchmark
  public boolean charClean()
  {
    return Sanwaf.isThreat(cleanChar, CHAR_XML);
  }

  @Benchmark
  public boolean charDirty()
  {
    return Sanwaf.isThreat(dirtyChar, CHAR_XML);
  }

  // ==================== Constant ====================

  @Benchmark
  public boolean constantClean()
  {
    return Sanwaf.isThreat(cleanConstant, CONSTANT_XML);
  }

  @Benchmark
  public boolean constantDirty()
  {
    return Sanwaf.isThreat(dirtyConstant, CONSTANT_XML);
  }

  // ==================== Regex (named pattern) ====================

  @Benchmark
  public boolean regexClean()
  {
    return Sanwaf.isThreat(cleanRegex, REGEX_XML);
  }

  @Benchmark
  public boolean regexDirty()
  {
    return Sanwaf.isThreat(dirtyRegex, REGEX_XML);
  }

  // ==================== Inline Regex ====================

  @Benchmark
  public boolean inlineRegexClean()
  {
    return Sanwaf.isThreat(cleanInlineRegex, INLINE_REGEX_XML);
  }

  @Benchmark
  public boolean inlineRegexDirty()
  {
    return Sanwaf.isThreat(dirtyInlineRegex, INLINE_REGEX_XML);
  }

  // ==================== Format ====================

  @Benchmark
  public boolean formatClean()
  {
    return Sanwaf.isThreat(cleanFormat, FORMAT_XML);
  }

  @Benchmark
  public boolean formatDirty()
  {
    return Sanwaf.isThreat(dirtyFormat, FORMAT_XML);
  }

  // ==================== Main ====================

  public static void main(String[] args) throws Exception
  {
    // Parse our custom flags before passing to JMH
    String pattern = null;
    String outputFile = null;
    boolean showHelp = false;

    for (int idx = 0; idx < args.length; idx++)
    {
      if ("-p".equals(args[idx]) && idx + 1 < args.length)
      {
        pattern = args[idx + 1];
        args[idx] = "";
        args[idx + 1] = "";
        idx++;
      }
      else if ("-o".equals(args[idx]) && idx + 1 < args.length)
      {
        outputFile = args[idx + 1];
        args[idx] = "";
        args[idx + 1] = "";
        idx++;
      }
      else if ("--help".equals(args[idx]))
      {
        showHelp = true;
      }
    }

    if (showHelp)
    {
      System.out.println("Sanwaf JMH Benchmark Runner");
      System.out.println("Usage: run-benchmarks.sh [options]");
      System.out.println();
      System.out.println("Options:");
      System.out.println("  -p <regex>        Run only benchmarks matching regex");
      System.out.println("                    e.g. -p \".*numeric.*\" or -p \".*Clean\"");
      System.out.println("  -o <file.json>    Save results to JSON file for comparison");
      System.out.println("  --compare <f.json> Compare current run against saved baseline");
      System.out.println("  --help            Show this help");
      System.out.println();
      System.out.println("  JMH flags are also accepted: -f <forks> -wi <warmups> -i <iters>");
      System.out.println();
      System.out.println("Benchmarks:");
      System.out.println("  stringClean/stringDirtyXss     Full pipeline (instance API)");
      System.out.println("  stringCleanShort/Long/Url      Clean string variants");
      System.out.println("  stringCleanHtmlEntities         Angle brackets, no tags");
      System.out.println("  stringDirtyXssEncoded/InText   Encoded & embedded XSS");
      System.out.println("  stringDirtyXssLong/Img         Long text & img-tag XSS");
      System.out.println("  numericClean/numericDirty       ItemNumeric");
      System.out.println("  integerClean/integerDirty       ItemNumeric (integer mode)");
      System.out.println("  numericDelimitedClean/Dirty     ItemNumericDelimited");
      System.out.println("  integerDelimitedClean/Dirty     ItemNumericDelimited (int)");
      System.out.println("  alphanumericClean/Dirty         ItemAlphanumeric");
      System.out.println("  alphanumericMoreClean/Dirty     ItemAlphanumericAndMore");
      System.out.println("  charClean/charDirty             ItemChar");
      System.out.println("  constantClean/constantDirty     ItemConstant");
      System.out.println("  regexClean/regexDirty           ItemRegex (named)");
      System.out.println("  inlineRegexClean/inlineRegexDirty  ItemRegex (inline)");
      System.out.println("  formatClean/formatDirty         ItemFormat");
      return;
    }

    // Build JMH include pattern
    String include = SanwafJmhBenchmark.class.getSimpleName();
    if (pattern != null)
    {
      include = SanwafJmhBenchmark.class.getSimpleName() + "\\." + pattern;
    }

    // Filter out empty args (our flags were blanked above)
    int count = 0;
    for (String arg : args) { if (!arg.isEmpty()) count++; }
    String[] filtered = new String[count];
    int fi = 0;
    for (String arg : args) { if (!arg.isEmpty()) filtered[fi++] = arg; }

    // Let JMH parse remaining args (forks, iterations, etc.)
    CommandLineOptions cmdOpts = new CommandLineOptions(filtered);

    OptionsBuilder builder = new OptionsBuilder();
    builder.parent(cmdOpts);
    builder.include(include);
    builder.addProfiler("gc");

    if (outputFile != null)
    {
      //noinspection JvmTaintAnalysis
      builder.resultFormat(ResultFormatType.JSON).result(outputFile);
    }

    Options opt = builder.build();
    Collection<RunResult> results = new Runner(opt).run();

    if (outputFile != null)
    {
      System.out.println("\nResults saved to: " + outputFile);
    }
  }
}
