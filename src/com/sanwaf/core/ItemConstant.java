package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Item subclass that validates values against a fixed set of allowed constants.
 *
 * <p>The allowed values are parsed from the type string at construction time
 * (e.g. {@code k(yes,no,maybe)}) and stored in insertion-order. A value
 * passes validation if it is empty or exactly matches one of the constants.
 */
final class ItemConstant extends Item {
  /** Default error-message prefix for constant validation failures. */
  static final String INVALID_CONSTANT = "Invalid Constant: ";
  /** The set of allowed constant values, in insertion order. */
  final Set<String> constants;
  /** JSON-encoded, human-readable representation of the allowed constants. */
  private final String constantsDisplay;

  /**
   * Constructs a constant item, parsing the allowed values from the type
   * string in the supplied configuration data.
   *
   * @param id item configuration data whose {@code type} field contains the
   *           constant specification
   */
  ItemConstant(ItemData id) {
    super(id);
    this.constants = parseConstants(id.type);
    this.constantsDisplay = JsonFormatter.jsonEncode(constants.toString());
  }

  /**
   * Returns {@code true} if the value is not one of the allowed constants.
   *
   * <p>Pre-validation checks are applied first. A {@code null} or empty
   * value is considered valid (unless caught by pre-validation).
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
    return value != null && !value.isEmpty() && !constants.contains(value);
  }

  /**
   * Inserts the human-readable constant list into the error message by
   * replacing its placeholder token.
   *
   * @param req      the servlet request being validated
   * @param errorMsg the error message template
   * @return the error message with the placeholder replaced
   */
  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg) {
    return replacePlaceholder(errorMsg, constantsDisplay);
  }

  /**
   * Returns error highlight points covering the entire value.
   *
   * @param shield the shield that owns this item
   * @param value  the invalid parameter value
   * @return a single point spanning the whole value, or an empty list if a
   *         masked error is configured
   */
  @Override
  List<Point> getErrorPoints(Shield shield, String value) {
    if (!maskError.isEmpty()) {
      return Collections.emptyList();
    }
    return Collections.singletonList(new Point(0, value.length()));
  }

  /**
   * Parses the allowed constant values from the type string.
   *
   * @param value the type string containing the constant specification
   * @return an insertion-ordered set of allowed values, or an empty set if
   *         no constants are found
   */
  private static Set<String> parseConstants(String value) {
    int start = value.indexOf(ItemFactory.CONSTANT);
    if (start >= 0) {
      String s = value.substring(start + ItemFactory.CONSTANT.length(), value.length() - 1);
      String[] parts = s.split(",");
      Set<String> result = new LinkedHashSet<>(parts.length * 2);
      result.addAll(Arrays.asList(parts));
      return result;
    }
    return Collections.emptySet();
  }

  /**
   * Returns a JSON fragment listing the allowed constant values.
   *
   * @return a JSON key-value pair for the {@code constant} property
   */
  @Override
  String getProperties() {
    StringBuilder sb = new StringBuilder();
    sb.append("\"constant\":\"");
    for (String s : constants) {
      sb.append(JsonFormatter.jsonEncode(s)).append(' ');
    }
    sb.append("\"");
    return sb.toString();
  }

  /**
   * Returns the default error message prefix for this item type.
   *
   * @return {@link #INVALID_CONSTANT}
   */
  @Override
  String getDefaultErrorMessage() {
    return INVALID_CONSTANT;
  }

  /**
   * Returns the type identifier for this item.
   *
   * @return {@link Types#CONSTANT}
   */
  @Override
  Types getType() {
    return Types.CONSTANT;
  }
}
