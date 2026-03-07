package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;

/**
 * Validates input values against one or more format patterns.
 *
 * <p>Format strings use a mini-language with the following character classes:
 * <ul>
 *   <li>{@code #} - any digit (0-9)</li>
 *   <li>{@code A} - uppercase letter (A-Z)</li>
 *   <li>{@code a} - lowercase letter (a-z)</li>
 *   <li>{@code c} - any letter (a-z, A-Z)</li>
 *   <li>{@code x} - any character</li>
 *   <li>Any other character is treated as a literal that must match exactly</li>
 * </ul>
 *
 * <p>Bracketed expressions after {@code #} provide range or list constraints:
 * <ul>
 *   <li>{@code #[1-12]} - numeric range (value must be between 1 and 12)</li>
 *   <li>{@code #[A,B,C]} - comma-separated list of accepted characters</li>
 *   <li>{@code #[mm-mm(+3)]} - date-variable range using {@code dd}, {@code mm},
 *       {@code yy}, or {@code yyyy} with optional arithmetic adjustments</li>
 * </ul>
 *
 * <p>Multiple alternative formats can be separated by {@code ||} (double pipe).
 * The value is accepted if it matches any one of the alternatives.
 *
 * <p>Special characters ({@code #}, {@code A}, {@code a}, {@code c}, {@code x},
 * {@code [}, {@code ]}, {@code |}, {@code :}, {@code =}, etc.) can be escaped
 * with a backslash to be treated as literals.
 */
final class ItemFormat extends Item {
  /** Default error message prefix for format validation failures. */
  static final String INVALID_FORMAT = "Invalid Format: ";
  /** Sentinel returned by {@link FmtBlock#match} to accept the value immediately. */
  private static final int ACCEPT_VALUE = Integer.MAX_VALUE;
  private static final PlaceholderBlock PLACEHOLDER = new PlaceholderBlock();
  private static final CharClassBlock ANY_CHAR = new CharClassBlock('x');
  private static final CharClassBlock DIGIT = new CharClassBlock('#');
  private static final CharClassBlock UPPER = new CharClassBlock('A');
  private static final CharClassBlock LOWER = new CharClassBlock('a');
  private static final CharClassBlock LETTER = new CharClassBlock('c');
  private static final ThreadLocal<Calendar> CACHED_CAL = ThreadLocal.withInitial(Calendar::getInstance);
  /** The raw format string as specified in configuration, before parsing. */
  String formatString = null;
  private boolean hasDateVariables;
  /** Parsed format alternatives; each inner list is a sequence of {@link FmtBlock}s. */
  final List<List<FmtBlock>> formatsBlocks = new ArrayList<>();

  /**
   * Constructs a format item and parses the format pattern from the item data.
   *
   * @param id item configuration data containing the format type string
   */
  ItemFormat(ItemData id) {
    super(id);
    setFormat(id.type);
  }

  /**
   * Returns error highlight points spanning the entire value.
   *
   * @param shield the active shield (unused for format items)
   * @param value  the input value being validated
   * @return a list containing a single point covering the full value,
   *         or an empty list if the value is empty or error masking is active
   */
  @Override
  List<Point> getErrorPoints(final Shield shield, final String value) {
    if (value.isEmpty() || !maskError.isEmpty()) {
      return Collections.emptyList();
    }
    return Collections.singletonList(new Point(0, value.length()));
  }

  /**
   * Validates the input value against all configured format alternatives.
   *
   * <p>Returns {@code false} (no error) if:
   * <ul>
   *   <li>The item is disabled</li>
   *   <li>No format patterns are configured</li>
   *   <li>The item is not required and the value is empty</li>
   *   <li>The value matches at least one of the format alternatives</li>
   * </ul>
   *
   * @param req         the servlet request
   * @param shield      the active shield
   * @param value       the input value to validate
   * @param doAllBlocks whether to process all detection blocks
   * @param log         whether to log violations
   * @return {@code true} if the value does not match any configured format
   */
  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log) {
    if (mode == Modes.DISABLED) {
      return false;
    }
    if (formatsBlocks.isEmpty()) {
      return false;
    }
    if (!required && value.isEmpty()) {
      return false;
    }
    boolean foundValidFormat = false;
    for (List<FmtBlock> formatBlocks : formatsBlocks) {
      if (!formatInError(value, formatBlocks)) {
        foundValidFormat = true;
        break;
      }
    }

    return !foundValidFormat;
  }

  /**
   * Tests whether the value fails a single parsed format (one alternative).
   *
   * <p>Iterates through the value character-by-character, matching each
   * against the corresponding {@link FmtBlock}. A block may advance the
   * position by more than one character (e.g., range blocks consume
   * multiple digits).
   *
   * @param value        the input value to test
   * @param formatBlocks the ordered list of format blocks for one alternative
   * @return {@code true} if the value does not match this format
   */
  private boolean formatInError(final String value, List<FmtBlock> formatBlocks) {
    if (formatBlocks.isEmpty()) {
      return false;
    }

    int formatLen = formatBlocks.size();
    if (!hasDateVariables && value.length() != formatLen) {
      return true;
    }

    Calendar cal = null;
    if (hasDateVariables) {
      cal = CACHED_CAL.get();
      cal.setTimeInMillis(System.currentTimeMillis());
    }

    for (int i = 0; i < value.length(); i++) {
      if (i >= formatLen) {
        return true;
      }
      FmtBlock block = formatBlocks.get(i);
      int advance = block.match(value, i, cal);
      if (advance == ACCEPT_VALUE) {
        return false;
      }
      if (advance < 0) {
        return true;
      }
      i += advance;
    }
    return false;
  }

  /**
   * Replaces backslash-escaped special characters with control-character
   * placeholders so they are not interpreted as format metacharacters
   * during parsing. The companion method {@link #unEscapedChar(char)}
   * reverses the mapping.
   *
   * @param s the raw format string potentially containing escape sequences
   * @return the string with escaped characters replaced by control characters
   */
  private static String escapeChars(String s) {
    char[] src = s.toCharArray();
    char[] dst = new char[src.length];
    int d = 0;
    for (int i = 0; i < src.length; i++) {
      if (src[i] == '\\' && i + 1 < src.length) {
        char next = src[i + 1];
        char replacement;
        switch (next) {
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
        i++;
      } else {
        dst[d++] = src[i];
      }
    }
    return new String(dst, 0, d);
  }

  /**
   * Maps a control-character placeholder back to the original literal
   * character it represents. Reverses the substitution performed by
   * {@link #escapeChars(String)}.
   *
   * @param c the control character to reverse-map
   * @return the original literal character, or {@code c} itself if no mapping exists
   */
  private static char unEscapedChar(char c) {
    switch (c) {
    case '\t':
      return '#';
    case '\n':
      return 'A';
    case '\r':
      return 'a';
    case '\f':
      return 'c';
    case '\b':
      return '[';
    case '\0':
      return ']';
    case '\1':
      return '|';
    case '\2':
      return 'x';
    case '\3':
      return ':';
    case '\4':
      return '=';
    case '\5':
      return '(';
    case '\6':
      return ')';
    case '\7':
      return '+';
    case '\016':
      return '-';
    case '\017':
      return ';';
    default:
      return c;
    }
  }

  /**
   * Inserts the JSON-encoded format string into the error message placeholder.
   *
   * @param req      the servlet request (unused)
   * @param errorMsg the error message template containing a placeholder
   * @return the error message with the format string substituted in
   */
  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg) {
    return replacePlaceholder(errorMsg, JsonFormatter.jsonEncode(formatString));
  }

  /**
   * Extracts the format specification from the type string and triggers parsing.
   * Also sets the {@link #hasDateVariables} flag if any date tokens are present.
   *
   * @param value the full type string (e.g., {@code "f{###-##-####}"})
   */
  private void setFormat(String value) {
    int start = value.indexOf(ItemFactory.FORMAT);
    if (start >= 0) {
      formatString = value.substring(start + ItemFactory.FORMAT.length(), value.length() - 1);
      parseFormats(formatString);
      hasDateVariables = formatString.contains("dd") || formatString.contains("mm") || formatString.contains("yy");
    }
  }

  /**
   * Splits a format string on {@code ||} delimiters and parses each
   * alternative into a list of {@link FmtBlock}s stored in {@link #formatsBlocks}.
   *
   * @param format the format string (may contain {@code ||} separators)
   */
  private void parseFormats(String format) {
    if (format.isEmpty()) {
      return;
    }
    String[] formats = format.split("\\|\\|");

    for (String thisFormat : formats) {
      formatsBlocks.add(parseFormat(thisFormat));
    }
  }

  /**
   * Parses a single format alternative into an ordered list of {@link FmtBlock}s.
   *
   * <p>Walks the format string character by character, converting metacharacters
   * into the appropriate block type. Bracketed expressions ({@code #[...]}) are
   * parsed as range, date-range, or comma-list blocks depending on their content.
   *
   * @param format a single format alternative (no {@code ||} separators)
   * @return the parsed block list, or an empty list if parsing fails
   */
  private List<FmtBlock> parseFormat(String format) {
    List<FmtBlock> formatBlocks = new ArrayList<>();
    format = escapeChars(format);
    int last = 0;

    while (true) {
      int pos = format.indexOf('#', last);
      if (pos < 0) {
        addRemainderCharsAsBlocks(format, last, formatBlocks);
        break;
      }

      for (int k = last; k < pos; k++) {
        formatBlocks.add(charToBlock(format.charAt(k)));
      }

      if (pos + 1 < format.length() && format.charAt(pos + 1) == '[') {
        int end = format.indexOf(']', pos);
        if (end < 0) {
          formatBlocks.clear();
          break;
        }
        String inner = format.substring(pos + 2, end);
        last = end + 1;

        if (containsDateVariable(inner)) {
          String rawBlock = format.substring(pos, end + 1);
          formatBlocks.add(new DateRangeBlock(rawBlock));
          int dash = inner.indexOf('-');
          if (dash >= 0) {
            int numDigits = inner.length() - (dash + 1);
            addPlaceholderBlocks(numDigits - 1, formatBlocks);
          }
        } else if (inner.contains(",")) {
          formatBlocks.add(new CommaListBlock(inner));
        } else {
          int dash = inner.indexOf('-');
          if (dash >= 0) {
            String minStr = inner.substring(0, dash);
            String maxStr = inner.substring(dash + 1);
            try {
              int min = Integer.parseInt(minStr);
              int max = Integer.parseInt(maxStr);
              int maxLen = String.valueOf(max).length();
              formatBlocks.add(new RangeBlock(min, max, maxLen));
              addPlaceholderBlocks(maxLen - 1, formatBlocks);
            } catch (NumberFormatException e) {
              formatBlocks.clear();
              break;
            }
          } else {
            formatBlocks.clear();
            break;
          }
        }
      } else {
        formatBlocks.add(DIGIT);
        last = pos + 1;
      }
    }
    return formatBlocks;
  }

  /**
   * Appends placeholder blocks to account for multi-digit range or date-range
   * blocks that consume more than one character position.
   *
   * @param count        number of placeholder blocks to add
   * @param formatBlocks the block list to append to
   */
  private static void addPlaceholderBlocks(int count, List<FmtBlock> formatBlocks) {
    for (int i = 0; i < count; i++) {
      formatBlocks.add(PLACEHOLDER);
    }
  }

  /**
   * Converts a single format character into the corresponding {@link FmtBlock}.
   * Metacharacters map to shared singleton instances; all others produce
   * a new {@link LiteralBlock}.
   *
   * @param c the format character (after escape processing)
   * @return the matching block instance
   */
  private static FmtBlock charToBlock(char c) {
    switch (c) {
    case 'x':
      return ANY_CHAR;
    case '#':
      return DIGIT;
    case 'A':
      return UPPER;
    case 'a':
      return LOWER;
    case 'c':
      return LETTER;
    default:
      return new LiteralBlock(unEscapedChar(c));
    }
  }

  /**
   * Converts all remaining characters in the format string (from position
   * {@code last} to the end) into blocks and appends them to the list.
   *
   * @param format       the format string
   * @param last         the starting position of the remaining characters
   * @param formatBlocks the block list to append to
   */
  private static void addRemainderCharsAsBlocks(String format, int last, List<FmtBlock> formatBlocks) {
    for (int k = last; k < format.length(); k++) {
      formatBlocks.add(charToBlock(format.charAt(k)));
    }
  }

  /**
   * Checks whether a string contains any date variable token
   * ({@code dd}, {@code mm}, or {@code yy}).
   *
   * @param s the string to inspect
   * @return {@code true} if at least one date variable is present
   */
  private static boolean containsDateVariable(String s) {
    return s.contains("dd") || s.contains("mm") || s.contains("yy");
  }

  /**
   * Returns the number of decimal digits in the given integer.
   *
   * @param n the integer (may be negative)
   * @return the digit count
   */
  private static int numDigits(int n) {
    if (n < 0)
      n = -n;
    if (n < 10)
      return 1;
    if (n < 100)
      return 2;
    if (n < 1000)
      return 3;
    if (n < 10000)
      return 4;
    return String.valueOf(n).length();
  }

  /**
   * Finds the position of the range separator ({@code -}) in a bracketed
   * expression, respecting nested parentheses used in date-variable
   * adjustment expressions such as {@code mm(+3)-mm}.
   *
   * @param inner the content between {@code [} and {@code ]}
   * @return the index of the separator, or {@code -1} if not found
   */
  private static int findRangeSep(String inner) {
    int depth = 0;
    for (int i = 0; i < inner.length(); i++) {
      char c = inner.charAt(i);
      if (c == '(')
        depth++;
      else if (c == ')')
        depth--;
      else if (c == '-' && depth == 0)
        return i;
    }
    return -1;
  }

  /**
   * Parses a date-value expression such as {@code mm}, {@code yyyy(+1)},
   * or a plain integer literal into a {@link DateVal}.
   *
   * @param s the expression string
   * @return the parsed {@link DateVal}, or {@code null} if the string is malformed
   */
  private static DateVal parseDateVal(String s) {
    int kind;
    int prefixLen;
    if (s.startsWith("yyyy")) {
      kind = DateVal.YEAR4;
      prefixLen = 4;
    } else if (s.startsWith("yy")) {
      kind = DateVal.YEAR2;
      prefixLen = 2;
    } else if (s.startsWith("mm")) {
      kind = DateVal.MONTH;
      prefixLen = 2;
    } else if (s.startsWith("dd")) {
      kind = DateVal.DAY;
      prefixLen = 2;
    } else {
      try {
        return new DateVal(DateVal.LITERAL, Integer.parseInt(s));
      } catch (NumberFormatException e) {
        return null;
      }
    }
    int adjust = 0;
    if (prefixLen < s.length() && s.charAt(prefixLen) == '(') {
      int close = s.indexOf(')', prefixLen);
      if (close < 0)
        return null;
      try {
        adjust = Integer.parseInt(s.substring(prefixLen + 1, close));
      } catch (NumberFormatException e) {
        return null;
      }
    }
    return new DateVal(kind, adjust);
  }

  /** {@inheritDoc} */
  @Override
  String getDefaultErrorMessage() {
    return INVALID_FORMAT;
  }

  /**
   * Returns a JSON fragment describing the format specification.
   *
   * @return JSON key-value pair with the format string
   */
  @Override
  String getProperties() {
    return "\"format\":\"" + JsonFormatter.jsonEncode(formatString) + "\"";
  }

  /** {@inheritDoc} */
  @Override
  Types getType() {
    return Types.FORMAT;
  }

  /**
   * Abstract base for format-matching blocks. Each block represents one
   * logical position in a parsed format and knows how to match against
   * one or more characters at a given position in the input string.
   */
  private static abstract class FmtBlock {
    /**
     * Attempts to match this block against the input at the given position.
     *
     * @param value the full input string
     * @param pos   the current character position to match
     * @param cal   a calendar instance for date-variable resolution, or {@code null}
     * @return the number of additional positions consumed beyond {@code pos}
     *         (0 means exactly one character matched), {@code -1} on mismatch,
     *         or {@link #ACCEPT_VALUE} to accept the entire value immediately
     */
    abstract int match(String value, int pos, Calendar cal);

    /**
     * Extracts up to {@code maxLen} digits from the value starting at {@code pos}
     * and checks whether the resulting number falls within [{@code min}, {@code max}].
     *
     * @param value  the input string
     * @param pos    the starting position
     * @param min    the minimum accepted value (inclusive)
     * @param max    the maximum accepted value (inclusive)
     * @param maxLen the maximum number of digits to consume
     * @return {@code maxLen - 1} (additional positions consumed) on match,
     *         or {@code -1} on mismatch
     */
    static int matchRange(String value, int pos, int min, int max, int maxLen) {
      int num = 0;
      for (int j = 0; j < maxLen; j++) {
        if (pos + j >= value.length()) {
          break;
        }
        char ch = value.charAt(pos + j);
        if (ch < '0' || ch > '9') {
          return -1;
        }
        num = num * 10 + (ch - '0');
      }
      return (num >= min && num <= max) ? maxLen - 1 : -1;
    }
  }

  /**
   * Matches a single literal character. The input character at the
   * current position must equal the expected character exactly.
   */
  private static final class LiteralBlock extends FmtBlock {
    /** The character the input must match at this position. */
    final char expected;

    /**
     * @param expected the literal character to match
     */
    LiteralBlock(char expected) {
      this.expected = expected;
    }

    /** {@inheritDoc} */
    int match(String value, int pos, Calendar cal) {
      return value.charAt(pos) == expected ? 0 : -1;
    }
  }

  /**
   * Matches a single character against a character class.
   * Supported types: {@code x} (any), {@code #} (digit),
   * {@code A} (uppercase), {@code a} (lowercase), {@code c} (any letter).
   * Instances are shared singletons for each type.
   */
  private static final class CharClassBlock extends FmtBlock {
    /** The character-class identifier. */
    final char type;

    /**
     * @param type the class identifier ({@code x}, {@code #}, {@code A},
     *             {@code a}, or {@code c})
     */
    CharClassBlock(char type) {
      this.type = type;
    }

    /** {@inheritDoc} */
    int match(String value, int pos, Calendar cal) {
      char c = value.charAt(pos);
      switch (type) {
      case 'x':
        return 0;
      case '#':
        return (c >= '0' && c <= '9') ? 0 : -1;
      case 'A':
        return (c >= 'A' && c <= 'Z') ? 0 : -1;
      case 'a':
        return (c >= 'a' && c <= 'z') ? 0 : -1;
      case 'c':
        return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) ? 0 : -1;
      default:
        return -1;
      }
    }
  }

  /**
   * Matches a single character against a comma-separated whitelist
   * specified in a bracketed expression (e.g., {@code #[A,B,C]}).
   * Only ASCII characters (code points 0-127) are supported.
   */
  private static final class CommaListBlock extends FmtBlock {
    /** Lookup table indexed by char value; {@code true} if the char is accepted. */
    final boolean[] validChars = new boolean[128];

    /**
     * Parses the comma-separated list and populates the lookup table.
     *
     * @param inner the content between brackets, e.g., {@code "A,B,C"}
     */
    CommaListBlock(String inner) {
      for (String s : inner.split(",")) {
        if (s.length() == 1 && s.charAt(0) < 128) {
          validChars[s.charAt(0)] = true;
        }
      }
    }

    /** {@inheritDoc} */
    int match(String value, int pos, Calendar cal) {
      char ch = value.charAt(pos);
      return (ch < 128 && validChars[ch]) ? 0 : -1;
    }
  }

  /**
   * Matches a multi-digit numeric value against a static integer range
   * (e.g., {@code #[1-12]}). Consumes up to {@code maxLen} digit
   * characters and validates that the parsed number is within bounds.
   */
  private static final class RangeBlock extends FmtBlock {
    final int min;
    final int max;
    final int maxLen;

    /**
     * @param min    the minimum accepted value (inclusive)
     * @param max    the maximum accepted value (inclusive)
     * @param maxLen the maximum number of digits to consume
     */
    RangeBlock(int min, int max, int maxLen) {
      this.min = min;
      this.max = max;
      this.maxLen = maxLen;
    }

    /** {@inheritDoc} */
    int match(String value, int pos, Calendar cal) {
      return matchRange(value, pos, min, max, maxLen);
    }
  }

  /**
   * Represents one side of a date-variable range expression. A {@code DateVal}
   * is either a literal integer or a date component ({@code dd}, {@code mm},
   * {@code yy}, {@code yyyy}) with an optional arithmetic adjustment.
   * At match time, {@link #resolve(Calendar)} evaluates the expression
   * against the current date.
   */
  private static final class DateVal {
    static final int LITERAL = 0, DAY = 1, MONTH = 2, YEAR2 = 3, YEAR4 = 4;
    final int kind;
    final int adjust;

    /**
     * @param kind   the value kind constant ({@link #LITERAL}, {@link #DAY},
     *               {@link #MONTH}, {@link #YEAR2}, or {@link #YEAR4})
     * @param adjust the arithmetic adjustment (offset for date kinds,
     *               or the literal value itself for {@link #LITERAL})
     */
    DateVal(int kind, int adjust) {
      this.kind = kind;
      this.adjust = adjust;
    }

    /**
     * Resolves this expression to a concrete integer using the given calendar.
     * For date kinds, the current date component is extracted and the
     * adjustment is applied. Values are capped at their natural maximum
     * (31 for days, 12 for months).
     *
     * @param cal the calendar representing the current date/time
     * @return the resolved integer value
     */
    int resolve(Calendar cal) {
      switch (kind) {
      case DAY: {
        int v = cal.get(Calendar.DAY_OF_MONTH) + adjust;
        return Math.min(v, 31);
      }
      case MONTH: {
        int v = cal.get(Calendar.MONTH) + 1 + adjust;
        return Math.min(v, 12);
      }
      case YEAR2:
        return cal.get(Calendar.YEAR) % 100 + adjust;
      case YEAR4:
        return cal.get(Calendar.YEAR) + adjust;
      default:
        return adjust;
      }
    }
  }

  /**
   * Matches a multi-digit numeric value against a date-variable range
   * (e.g., {@code #[mm-mm(+3)]}). The range bounds are resolved at
   * match time using the current date from the provided {@link Calendar}.
   */
  private static final class DateRangeBlock extends FmtBlock {
    /** The minimum bound expression, or {@code null} if parsing failed. */
    final DateVal min;
    /** The maximum bound expression, or {@code null} if parsing failed. */
    final DateVal max;

    /**
     * Parses a raw date-range block string (e.g., {@code "#[mm-12]"}).
     *
     * @param rawBlock the full block including the leading {@code #[} and trailing {@code ]}
     */
    DateRangeBlock(String rawBlock) {
      String inner = rawBlock.substring(2, rawBlock.length() - 1);
      int sep = findRangeSep(inner);
      if (sep < 0) {
        min = null;
        max = null;
        return;
      }
      min = parseDateVal(inner.substring(0, sep));
      max = parseDateVal(inner.substring(sep + 1));
    }

    /**
     * {@inheritDoc}
     *
     * <p>Returns {@link #ACCEPT_VALUE} if the block was not parsed
     * successfully or no calendar is available (effectively skipping
     * validation for this position).
     */
    int match(String value, int pos, Calendar cal) {
      if (min == null || max == null || cal == null) {
        return ACCEPT_VALUE;
      }
      int minVal = min.resolve(cal);
      int maxVal = max.resolve(cal);
      return matchRange(value, pos, minVal, maxVal, numDigits(maxVal));
    }
  }

  /**
   * A no-op block that always matches. Used to pad block lists so that
   * their size equals the expected input length when a preceding range
   * or date-range block consumes multiple characters.
   */
  private static final class PlaceholderBlock extends FmtBlock {
    /** Always returns 0 (match with no additional advance). */
    int match(String value, int pos, Calendar cal) {
      return 0;
    }
  }
}
