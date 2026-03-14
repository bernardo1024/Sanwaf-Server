package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Collections;
import java.util.List;

/**
 * Item subclass that unconditionally rejects any parameter not explicitly
 * configured in the shield.
 *
 * <p>{@code ItemStrict} is used as a sentinel: its {@link #inError} method
 * always returns {@code false} because the framework treats the mere presence
 * of an unconfigured parameter as a violation before {@code inError} is
 * called. The item simply carries a descriptive error message.
 */
class ItemStrict extends Item {

  /**
   * Constructs a strict item with the given error message.
   *
   * @param s the error message to report for unconfigured parameters
   */
  ItemStrict(String s) {
    msg = s;
  }

  /**
   * Always returns {@code false}.
   *
   * <p>Strict-mode violations are detected at a higher level; this method
   * is not the enforcement point.
   *
   * @param req        the servlet request being validated
   * @param shield     the shield that owns this item
   * @param value      the parameter value
   * @param doAllBlocks unused by this implementation
   * @param log        unused by this implementation
   * @return {@code false} always
   */
  @Override
  boolean inError(ServletRequest req, Shield shield, String value, boolean doAllBlocks, boolean log) {
    return false;
  }

  /**
   * Returns an empty list; strict items do not highlight specific offending
   * character ranges.
   *
   * @param shield the shield that owns this item
   * @param value  the parameter value
   * @return an empty list
   */
  @Override
  List<Point> getErrorPoints(Shield shield, String value) {
    return Collections.emptyList();
  }

  /**
   * Returns the type identifier for this item.
   *
   * @return {@link Types#STRICT}
   */
  @Override
  Types getType() {
    return Types.STRICT;
  }
}
