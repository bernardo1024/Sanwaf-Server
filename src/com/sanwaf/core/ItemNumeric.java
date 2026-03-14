package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Validation item for numeric parameter values (integer or floating-point).
 *
 * <p>Validates that a parameter contains only digits, an optional leading
 * minus sign, and (for non-integer mode) at most one decimal point.
 * Optional min/max value bounds are enforced after format validation.
 */
class ItemNumeric extends Item {
  /** Default error message returned when numeric validation fails. */
  static final String INVALID_NUMBER = "Invalid Number";
  /** {@code true} if this item accepts only integers (no decimal point). */
  final boolean isInt;

  /**
   * Constructs a numeric validation item.
   *
   * @param id    parsed item configuration data
   * @param isInt {@code true} to restrict to integer values,
   *              {@code false} to allow a single decimal point
   */
  ItemNumeric(ItemData id, boolean isInt) {
    super(id);
    this.isInt = isInt;
  }

  /**
   * Tests whether a character is invalid in a numeric value.
   *
   * <p>Digits {@code 0}-{@code 9} are always accepted. For non-integer
   * items, the first decimal point encountered is accepted and recorded
   * in {@code foundDot}; subsequent dots are rejected.
   *
   * <p>Leading sign characters are <em>not</em> handled here; callers
   * must skip a leading {@code '-'} before invoking this method.
   *
   * @param c        the character to test
   * @param foundDot single-element array used as a mutable flag; element 0
   *                 is set to {@code true} when a decimal point is consumed
   * @return {@code true} if {@code c} is not a valid numeric character
   */
  boolean isNotNumericChar(char c, boolean[] foundDot) {
    if (c >= '0' && c <= '9') {
      return false;
    }
    if (!isInt && c == '.' && !foundDot[0]) {
      foundDot[0] = true;
      return false;
    }
    return true;
  }

  /**
   * Identifies character ranges within {@code value} that are not valid
   * numeric characters.
   *
   * <p>If {@link #maskError} is set, an empty list is returned to suppress
   * detailed error highlighting. A leading {@code '-'} sign is skipped.
   *
   * @param shield the active shield (unused by this implementation)
   * @param value  the raw parameter value to scan
   * @return list of {@link Point} ranges marking invalid character spans,
   *         or an empty list if the value is fully valid or masking is active
   */
  @Override
  List<Point> getErrorPoints(final Shield shield, final String value) {
    if (!maskError.isEmpty()) {
      return Collections.emptyList();
    }
    List<Point> points = null;
    final int len = value.length();
    int errStart = -1;
    boolean[] foundDot = { false };
    int start = 0;
    if (len > 0 && value.charAt(0) == '-') {
      start = 1;
    }

    for (int i = start; i < len; i++) {
      if (isNotNumericChar(value.charAt(i), foundDot)) {
        errStart = checkErrStart(errStart, i);
      } else {
        if (errStart >= 0) {
          if (points == null) {
            points = new ArrayList<>();
          }
          points.add(new Point(errStart, i));
          errStart = -1;
        }
      }
    }
    if (errStart >= 0) {
      if (points == null) {
        points = new ArrayList<>();
      }
      points.add(new Point(errStart, len));
    }
    return points != null ? points : Collections.emptyList();
  }

  /**
   * Scans a substring of {@code value} for non-numeric characters and appends
   * error ranges to the supplied list.
   *
   * <p>Used by {@link ItemNumericDelimited} to validate individual segments
   * between delimiters. A leading {@code '-'} at position {@code from} is
   * skipped.
   *
   * @param value  the full parameter value
   * @param from   start index (inclusive) of the segment to check
   * @param to     end index (exclusive) of the segment to check
   * @param points mutable list to which invalid-character {@link Point}
   *               ranges are appended
   */
  void getErrorPointsRange(final String value, int from, int to, List<Point> points) {
    int errStart = -1;
    boolean[] foundDot = { false };
    int start = from;
    if (from < to && value.charAt(from) == '-') {
      start = from + 1;
    }
    for (int i = start; i < to; i++) {
      if (isNotNumericChar(value.charAt(i), foundDot)) {
        errStart = checkErrStart(errStart, i);
      } else {
        if (errStart >= 0) {
          points.add(new Point(errStart, i));
          errStart = -1;
        }
      }
    }
    if (errStart >= 0) {
      points.add(new Point(errStart, to));
    }
  }

  /**
   * Lazily initialises an error-span start index.
   *
   * @param errStart current span start, or {@code -1} if no span is open
   * @param i        candidate start index
   * @return {@code errStart} if a span is already open, otherwise {@code i}
   */
  private int checkErrStart(int errStart, int i) {
    if (errStart < 0) {
      errStart = i;
    }
    return errStart;
  }

  /**
   * Checks whether the parsed numeric value falls outside the configured
   * min/max value bounds.
   *
   * <p>If no bounds are configured (defaults of {@code Integer.MAX_VALUE}
   * and {@code Integer.MIN_VALUE}), the check is skipped. Empty values are
   * allowed when the item is not required.
   *
   * @param value the string representation of the number to check
   * @return {@code true} if the value exceeds the configured bounds or
   *         cannot be parsed
   */
  private boolean isMaxMinValueError(String value) {
    if (maxValue >= Integer.MAX_VALUE && minValue <= Integer.MIN_VALUE) {
      return false;
    }
    if (value.isEmpty() && !required) {
      return false;
    }
    try {
      if (isInt) {
        int digitCount = value.length();
        if (digitCount > 0 && value.charAt(0) == '-') {
          digitCount--;
        }
        if (digitCount <= 15) {
          long v = parseLongRange(value, 0, value.length());
          return v > maxValue || v < minValue;
        }
      }
      double d = Double.parseDouble(value);
      if (d > maxValue || d < minValue) {
        return true;
      }
    } catch (NumberFormatException nfe) {
      return true;
    }
    return false;
  }

  /**
   * Validates that the parameter value is a well-formed number within
   * configured bounds.
   *
   * <p>Pre-validation checks (disabled mode, URI filter, size limits) are
   * run first. Then each character is verified as a valid digit (or leading
   * minus sign, or single decimal point for floats). Finally, min/max value
   * bounds are enforced.
   *
   * @param req         the current servlet request
   * @param shield      the active shield configuration
   * @param value       the parameter value to validate
   * @param doAllBlocks {@code true} to evaluate all block-mode rules
   * @param log         {@code true} to log validation failures
   * @return {@code true} if the value is not a valid number
   */
  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log) {
    if (hasPreValidationError(req, value)) {
      return true;
    }
    boolean[] foundDot = { false };
    final int len = value.length();
    for (int i = 0; i < len; i++) {
      char c = value.charAt(i);
      if (i == 0 && c == '-' && len > 1) {
        continue;
      }
      if (isNotNumericChar(c, foundDot)) {
        return true;
      }
    }
    return isMaxMinValueError(value);
  }

  /**
   * Validates a substring segment of {@code value} as a numeric value.
   *
   * <p>Used by {@link ItemNumericDelimited} to validate individual segments
   * between delimiters. Checks segment length against min/max size, verifies
   * character validity, and enforces value bounds.
   *
   * @param value the full parameter value
   * @param from  start index (inclusive) of the segment
   * @param to    end index (exclusive) of the segment
   * @return {@code true} if the segment is not a valid number
   */
  boolean inErrorRange(final String value, int from, int to) {
    int segLen = to - from;
    if (!required && segLen == 0) {
      return false;
    }
    if (segLen < min || segLen > max) {
      return true;
    }
    boolean[] foundDot = { false };
    for (int i = from; i < to; i++) {
      char c = value.charAt(i);
      if (i == from && c == '-' && segLen > 1) {
        continue;
      }
      if (isNotNumericChar(c, foundDot)) {
        return true;
      }
    }
    return isMaxMinValueErrorRange(value, from, to);
  }

  /**
   * Checks whether a substring segment's parsed numeric value falls outside
   * the configured min/max value bounds.
   *
   * @param value the full parameter value
   * @param from  start index (inclusive) of the segment
   * @param to    end index (exclusive) of the segment
   * @return {@code true} if the segment value exceeds bounds or cannot be parsed
   */
  private boolean isMaxMinValueErrorRange(String value, int from, int to) {
    if (maxValue >= Integer.MAX_VALUE && minValue <= Integer.MIN_VALUE) {
      return false;
    }
    if ((to - from) == 0 && !required) {
      return false;
    }
    try {
      if (isInt) {
        int digitCount = to - from;
        if (from < to && value.charAt(from) == '-') {
          digitCount--;
        }
        if (digitCount <= 15) {
          long v = parseLongRange(value, from, to);
          return v > maxValue || v < minValue;
        }
      }
      double d = Double.parseDouble(value.substring(from, to));
      return d > maxValue || d < minValue;
    } catch (NumberFormatException nfe) {
      return true;
    }
  }

  /**
   * Parses a long integer from a substring without allocating a new string.
   *
   * <p>Assumes the substring contains only digits and an optional leading
   * {@code '-'}. No overflow checking is performed; callers should ensure
   * the digit count is within safe bounds before calling.
   *
   * @param s    the source string
   * @param from start index (inclusive)
   * @param to   end index (exclusive)
   * @return the parsed long value
   */
  private static long parseLongRange(String s, int from, int to) {
    int i = from;
    boolean negative = false;
    if (s.charAt(i) == '-') {
      negative = true;
      i++;
    }
    long result = 0;
    for (; i < to; i++) {
      result = result * 10 + (s.charAt(i) - '0');
    }
    return negative ? -result : result;
  }

  /**
   * Returns the default error message for numeric validation failures.
   *
   * @return {@value #INVALID_NUMBER}
   */
  @Override
  String getDefaultErrorMessage() {
    return INVALID_NUMBER;
  }

  /**
   * Returns the item type identifier.
   *
   * @return {@link Types#NUMERIC}
   */
  @Override
  Types getType() {
    return Types.NUMERIC;
  }
}
