package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Collections;
import java.util.List;

/**
 * Item subclass that validates single-character values.
 *
 * <p>A value passes validation if it is {@code null} or contains at most one
 * character. Any string longer than one character is considered invalid.
 */
final class ItemChar extends Item {
  /** Default error-message prefix for char validation failures. */
  static final String INVALID_CHAR = "Invalid Char: ";

  /**
   * Constructs a char item from the supplied configuration data.
   *
   * @param id item configuration data
   */
  ItemChar(ItemData id) {
    super(id);
  }

  /**
   * Returns {@code true} if the value is not a single character.
   *
   * <p>Pre-validation checks (length bounds, required, etc.) are applied
   * first. A {@code null} value is considered valid.
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
    if (value == null) {
      return false;
    }
    return value.length() > 1;
  }

  /**
   * Returns error highlight points covering the entire value.
   *
   * @param shield the shield that owns this item
   * @param value  the invalid parameter value
   * @return a single point spanning the whole value, or an empty list if
   *         the value is {@code null} or a masked error is configured
   */
  @Override
  List<Point> getErrorPoints(Shield shield, String value) {
    if (value == null || !maskError.isEmpty()) {
      return Collections.emptyList();
    }
    return Collections.singletonList(new Point(0, value.length()));
  }

  /**
   * Returns the default error message prefix for this item type.
   *
   * @return {@link #INVALID_CHAR}
   */
  @Override
  String getDefaultErrorMessage() {
    return INVALID_CHAR;
  }

  /**
   * Returns the type identifier for this item.
   *
   * @return {@link Types#CHAR}
   */
  @Override
  Types getType() {
    return Types.CHAR;
  }
}
