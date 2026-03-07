package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Item subclass that validates alphanumeric-only values (ASCII letters and
 * digits: {@code a-z}, {@code A-Z}, {@code 0-9}).
 *
 * <p>Any character outside those ranges causes validation to fail.
 * Subclasses (e.g. {@link ItemAlphanumericAndMore}) override
 * {@link #isInvalidChar(char)} to allow additional characters.
 */
class ItemAlphanumeric extends Item {
  /** Default error-message prefix for alphanumeric validation failures. */
  static final String INVALID_AN = "Invalid Alphanumeric: ";

  /**
   * Constructs an alphanumeric item from the supplied configuration data.
   *
   * @param id item configuration data
   */
  ItemAlphanumeric(ItemData id) {
    super(id);
  }

  /**
   * Tests whether a character is invalid for this item type.
   *
   * <p>This implementation rejects any non-alphanumeric character.
   * Subclasses may override to permit additional characters.
   *
   * @param c the character to test
   * @return {@code true} if the character is not allowed
   */
  boolean isInvalidChar(char c) {
    return isNotAlphanumeric(c);
  }

  /**
   * Returns error highlight points identifying contiguous runs of invalid
   * characters within the value.
   *
   * @param shield the shield that owns this item
   * @param value  the invalid parameter value
   * @return a list of {@link Point} ranges covering invalid character runs,
   *         or an empty list if the value is {@code null} or a masked error
   *         is configured
   */
  @Override
  List<Point> getErrorPoints(Shield shield, final String value) {
    if (value == null || !maskError.isEmpty()) {
      return Collections.emptyList();
    }
    List<Point> points = null;
    int start = -1;
    int len = value.length();
    for (int i = 0; i < len; i++) {
      if (isInvalidChar(value.charAt(i))) {
        if (start < 0) {
          start = i;
        }
      } else {
        if (start >= 0) {
          if (points == null) {
            points = new ArrayList<>();
          }
          points.add(new Point(start, i));
          start = -1;
        }
      }
    }
    if (start >= 0) {
      if (points == null) {
        points = new ArrayList<>();
      }
      points.add(new Point(start, len));
    }
    return points != null ? points : Collections.emptyList();
  }

  /**
   * Returns {@code true} if the value contains any non-alphanumeric character.
   *
   * <p>Pre-validation checks (length bounds, required, etc.) are applied first.
   *
   * @param req        the servlet request being validated
   * @param shield     the shield that owns this item
   * @param value      the parameter value to validate
   * @param doAllBlocks unused by this implementation
   * @param log        unused by this implementation
   * @return {@code true} if the value fails validation
   */
  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log) {
    if (hasPreValidationError(req, value)) {
      return true;
    }
    for (int i = 0; i < value.length(); i++) {
      if (isInvalidChar(value.charAt(i))) {
        return true;
      }
    }
    return false;
  }

  /**
   * Tests whether a character falls outside the ASCII alphanumeric ranges
   * ({@code 0-9}, {@code A-Z}, {@code a-z}).
   *
   * @param c the character to test
   * @return {@code true} if the character is not alphanumeric
   */
  static boolean isNotAlphanumeric(char c) {
    return (c < 0x30 || (c >= 0x3a && c <= 0x40) || (c > 0x5a && c <= 0x60) || c > 0x7a);
  }

  /**
   * Returns the default error message prefix for this item type.
   *
   * @return {@link #INVALID_AN}
   */
  @Override
  String getDefaultErrorMessage() {
    return INVALID_AN;
  }

  /**
   * Returns the type identifier for this item.
   *
   * @return {@link Types#ALPHANUMERIC}
   */
  @Override
  Types getType() {
    return Types.ALPHANUMERIC;
  }
}
