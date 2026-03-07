package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Arrays;

/**
 * Item subclass that validates alphanumeric values plus a configurable set of
 * additional allowed characters.
 *
 * <p>The extra characters are specified inside the type string (e.g.
 * {@code a{.,-}}) and are parsed at construction time. Whitespace escapes
 * such as {@code \s}, {@code \t}, {@code \n}, and {@code \r} are supported.
 * ASCII extra characters are looked up via a 128-element boolean table;
 * non-ASCII extras use a sorted array with binary search.
 */
final class ItemAlphanumericAndMore extends ItemAlphanumeric {
  /** Default error-message prefix for alphanumeric-and-more validation failures. */
  static final String INVALID_AN_MORE = "Invalid Alphanumeric And More: ";
  /** Escape token representing a space character in configuration. */
  static final String SPACE = "\\s";
  /** Escape token representing a tab character in configuration. */
  static final String TAB = "\\t";
  /** Escape token representing a newline character in configuration. */
  static final String NEWLINE = "\\n";
  /** Escape token representing a carriage return in configuration. */
  static final String CARRIAGE_RETURN = "\\r";
  /** Human-readable label for a space character in error messages. */
  static final String SPACE_LONG = "<space>";
  /** Human-readable label for a tab character in error messages. */
  static final String TAB_LONG = "<tab>";
  /** Human-readable label for a newline character in error messages. */
  static final String NEWLINE_LONG = "<newline>";
  /** Human-readable label for a carriage return in error messages. */
  static final String CARRIAGE_RETURN_LONG = "<carriage return>";

  /** The additional characters allowed beyond alphanumeric. */
  final char[] moreChars;
  /** JSON-encoded, human-readable representation of {@link #moreChars}. */
  private final String moreCharsDisplay;
  /** Fast lookup table for ASCII extra characters (index = char value). */
  private final boolean[] asciiLookup;
  /** Sorted array of non-ASCII extra characters for binary search. */
  private final char[] nonAsciiChars;

  /**
   * Constructs an alphanumeric-and-more item, parsing the extra allowed
   * characters from the type string in the supplied configuration data.
   *
   * @param id item configuration data whose {@code type} field contains the
   *           extra-character specification
   */
  ItemAlphanumericAndMore(ItemData id) {
    super(id);
    int start = id.type.indexOf(ItemFactory.SEP_START);
    int end = id.type.lastIndexOf(ItemFactory.SEP_END);
    this.moreChars = getMoreCharArray(id.type.substring(start + ItemFactory.SEP_START.length(), end));
    this.asciiLookup = new boolean[128];
    int nonAsciiCount = 0;
    for (char c : moreChars) {
      if (c < 128) {
        asciiLookup[c] = true;
      } else {
        nonAsciiCount++;
      }
    }
    char[] nac = new char[nonAsciiCount];
    int idx = 0;
    for (char c : moreChars) {
      if (c >= 128) {
        nac[idx++] = c;
      }
    }
    Arrays.sort(nac);
    this.nonAsciiChars = nac;
    this.moreCharsDisplay = JsonFormatter.jsonEncode(handleSpecialChars(moreChars));
  }

  /**
   * Tests whether a character is invalid for this item type.
   *
   * <p>A character is invalid only if it is neither alphanumeric nor present
   * in the configured extra-character set.
   *
   * @param c the character to test
   * @return {@code true} if the character is not allowed
   */
  @Override
  boolean isInvalidChar(char c) {
    return isNotAlphanumeric(c) && notInMoreChars(c);
  }

  /**
   * Tests whether a character is absent from the extra-character set.
   *
   * @param c the character to look up
   * @return {@code true} if the character is not in the extra-character set
   */
  private boolean notInMoreChars(char c) {
    if (c < 128) {
      return !asciiLookup[c];
    }
    return Arrays.binarySearch(nonAsciiChars, c) < 0;
  }

  /**
   * Inserts the human-readable extra-character list into the error message
   * by replacing its placeholder token.
   *
   * @param req      the servlet request being validated
   * @param errorMsg the error message template
   * @return the error message with the placeholder replaced
   */
  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg) {
    return replacePlaceholder(errorMsg, moreCharsDisplay);
  }

  /**
   * Replaces literal whitespace characters in the given char array's string
   * representation with human-readable labels (e.g. {@code <space>}).
   *
   * @param chars the character array to process
   * @return a display-friendly string with whitespace labels
   */
  static String handleSpecialChars(char[] chars) {
    String s = String.valueOf(chars);
    s = replaceString(s, " ", SPACE_LONG);
    s = replaceString(s, "\t", TAB_LONG);
    s = replaceString(s, "\n", NEWLINE_LONG);
    s = replaceString(s, "\r", CARRIAGE_RETURN_LONG);
    return s;
  }

  /**
   * Parses an extra-character specification string, converting escape tokens
   * ({@code \s}, {@code \t}, {@code \n}, {@code \r}) into their literal
   * character equivalents, and returns the result as a char array.
   *
   * @param s the extra-character specification string
   * @return a char array of the additional allowed characters
   */
  static char[] getMoreCharArray(String s) {
    s = replaceString(s, SPACE, " ");
    s = replaceString(s, TAB, "\t");
    s = replaceString(s, NEWLINE, "\n");
    s = replaceString(s, CARRIAGE_RETURN, "\r");
    return s.toCharArray();
  }

  /**
   * Replaces all occurrences of {@code from} with {@code to} in the given
   * string.
   *
   * @param s    the source string
   * @param from the substring to find
   * @param to   the replacement substring
   * @return the resulting string after replacement
   */
  static String replaceString(String s, String from, String to) {
    return s.replace(from, to);
  }

  /**
   * Returns a JSON fragment describing the extra allowed characters.
   *
   * @return a JSON key-value pair for the {@code morechars} property
   */
  @Override
  String getProperties() {
    return "\"morechars\":\"" + JsonFormatter.jsonEncode(new String(moreChars)) + "\"";
  }

  /**
   * Returns the default error message prefix for this item type.
   *
   * @return {@link #INVALID_AN_MORE}
   */
  @Override
  String getDefaultErrorMessage() {
    return INVALID_AN_MORE;
  }

  /**
   * Returns the type identifier for this item.
   *
   * @return {@link Types#ALPHANUMERIC_AND_MORE}
   */
  @Override
  Types getType() {
    return Types.ALPHANUMERIC_AND_MORE;
  }
}
