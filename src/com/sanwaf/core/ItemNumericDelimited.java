package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Validation item for delimiter-separated lists of numeric values.
 *
 * <p>Splits the parameter value on a configurable delimiter string and
 * validates each segment independently as a numeric value using the
 * rules inherited from {@link ItemNumeric}. For example, with delimiter
 * {@code ","} the value {@code "1,2,3"} is valid while {@code "1,abc,3"}
 * is not.
 *
 * <p>The delimiter is extracted from the type specification between
 * {@link ItemFactory#SEP_START} and {@link ItemFactory#SEP_END} markers.
 */
final class ItemNumericDelimited extends ItemNumeric {
  /** The string used to split the parameter value into numeric segments. */
  final String delimiter;

  /**
   * Constructs a delimited-numeric validation item.
   *
   * <p>Parses the delimiter from the type specification in {@code id.type}.
   *
   * @param id    parsed item configuration data
   * @param isInt {@code true} to restrict each segment to integer values
   */
  ItemNumericDelimited(ItemData id, boolean isInt) {
    super(id, isInt);
    int start = id.type.indexOf(ItemFactory.SEP_START);
    int end = id.type.lastIndexOf(ItemFactory.SEP_END);
    this.delimiter = id.type.substring(start + ItemFactory.SEP_START.length(), end);
  }

  /**
   * Identifies non-numeric character ranges across all delimited segments.
   *
   * <p>Splits the value on the configured delimiter and delegates each
   * segment to {@link ItemNumeric#getErrorPointsRange}. Returns an empty
   * list when masking is active, the value is {@code null}, or the
   * delimiter is empty.
   *
   * @param shield the active shield (passed through to superclass)
   * @param value  the raw parameter value to scan
   * @return list of {@link Point} ranges marking invalid characters,
   *         or an empty list if fully valid
   */
  @Override
  List<Point> getErrorPoints(final Shield shield, final String value) {
    if (!maskError.isEmpty() || value == null || delimiter.isEmpty()) {
      return Collections.emptyList();
    }
    List<Point> points = new ArrayList<>();
    int start = 0;
    int pos;
    while ((pos = value.indexOf(delimiter, start)) >= 0) {
      if (start < pos) {
        super.getErrorPointsRange(value, start, pos, points);
      }
      start = pos + delimiter.length();
    }
    if (start < value.length()) {
      super.getErrorPointsRange(value, start, value.length(), points);
    }
    return points.isEmpty() ? Collections.emptyList() : points;
  }

  /**
   * Validates that every segment between delimiters is a valid number.
   *
   * <p>If the item is disabled or the value is {@code null}, returns
   * {@code false}. If the delimiter is empty, falls back to plain numeric
   * validation via the superclass. Otherwise, splits the value on the
   * delimiter and validates each segment with
   * {@link ItemNumeric#inErrorRange}.
   *
   * @param req         the current servlet request
   * @param shield      the active shield configuration
   * @param value       the parameter value to validate
   * @param doAllBlocks {@code true} to evaluate all block-mode rules
   * @param log         {@code true} to log validation failures
   * @return {@code true} if any segment is not a valid number
   */
  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log) {
    if (mode == Modes.DISABLED || value == null) {
      return false;
    }
    if (delimiter.isEmpty()) {
      return super.inError(req, shield, value, doAllBlocks, log);
    }
    if (isUriInvalid(req)) {
      return true;
    }
    int start = 0;
    int pos;
    while ((pos = value.indexOf(delimiter, start)) >= 0) {
      if (start < pos && super.inErrorRange(value, start, pos)) {
        return true;
      }
      start = pos + delimiter.length();
    }
    if (start < value.length()) {
      return super.inErrorRange(value, start, value.length());
    }
    return false;
  }

  /**
   * Substitutes the delimiter value into the error message placeholder.
   *
   * @param req      the current servlet request
   * @param errorMsg the error message template containing a placeholder
   * @return the error message with the delimiter inserted (JSON-encoded)
   */
  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg) {
    return replacePlaceholder(errorMsg, JsonFormatter.jsonEncode(delimiter));
  }

  /**
   * Returns a JSON fragment describing this item's delimiter property.
   *
   * @return JSON key-value pair for the delimiter, with the value
   *         JSON-encoded
   */
  @Override
  String getProperties() {
    return "\"delimiter\":\"" + JsonFormatter.jsonEncode(delimiter) + "\"";
  }

  /**
   * Returns the item type identifier.
   *
   * @return {@link Types#NUMERIC_DELIMITED}
   */
  @Override
  Types getType() {
    return Types.NUMERIC_DELIMITED;
  }
}
