package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Collections;
import java.util.List;

/**
 * Item subclass that accepts any value without content-based validation.
 *
 * <p>Only pre-validation checks (length bounds, required, related-field
 * constraints, etc.) are applied. The value's content is never inspected,
 * making this the most permissive item type.
 */
class ItemOpen extends Item {
  /**
   * Constructs an open item from the supplied configuration data.
   *
   * @param id item configuration data
   */
  ItemOpen(ItemData id) {
    super(id);
  }

  /**
   * Returns {@code true} only if a pre-validation check fails.
   *
   * <p>No content-based validation is performed on the value itself.
   *
   * @param req        the servlet request being validated
   * @param shield     the shield that owns this item
   * @param value      the parameter value to validate
   * @param doAllBlocks unused by this implementation
   * @param log        unused by this implementation
   * @return {@code true} if a pre-validation check fails
   */
  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log) {
    return hasPreValidationError(req, value);
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
   * Returns the type identifier for this item.
   *
   * @return {@link Types#OPEN}
   */
  @Override
  Types getType() {
    return Types.OPEN;
  }
}
