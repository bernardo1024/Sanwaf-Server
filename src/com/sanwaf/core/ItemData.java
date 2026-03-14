package com.sanwaf.core;

import com.sanwaf.log.Logger;

/**
 * Immutable data holder for item configuration parsed from XML.
 *
 * <p>An {@code ItemData} instance carries every attribute needed to construct
 * a concrete {@link Item} subclass. It is created by
 * {@link ItemFactory#parseItem} and passed to
 * {@link ItemFactory#getNewItem(ItemData)}.
 */
class ItemData {
  /** Parameter name. */
  final String name;
  /** Human-readable display name for error messages. */
  final String display;
  /** Owning shield, or {@code null} when parsing global items. */
  final Shield shield;
  /** Type string (e.g. "s", "n", "r{...}") that selects the Item subclass. */
  final String type;
  /** Minimum allowed character length of the parameter value. */
  final int min;
  /** Maximum allowed character length of the parameter value. */
  final int max;
  /** Custom error message, or empty string for the default. */
  final String msg;
  /** Separator-delimited URI restriction string, or empty. */
  final String uri;
  /** Validation mode (BLOCK, DETECT, or DISABLED). */
  final Modes mode;
  /** Logger instance for recording validation results. */
  final Logger logger;
  /** Whether a non-empty value is required. */
  final boolean required;
  /** Maximum allowed numeric value. */
  final double maxValue;
  /** Minimum allowed numeric value. */
  final double minValue;
  /** Mask applied to the parameter value in error output. */
  final String maskError;
  /** Raw related-field validation expression. */
  final String related;
  /** Parsed related-field validation blocks. */
  final RelationValidator.Block[] relatedBlocks;

  /**
   * Convenience constructor with sensible defaults for optional fields.
   *
   * @param shield  owning shield, or {@code null}
   * @param name    parameter name
   * @param mode    validation mode
   * @param display display name
   * @param type    type string
   * @param msg     custom error message
   * @param uri     URI restriction string
   * @param max     maximum character length
   * @param min     minimum character length
   */
  ItemData(Shield shield, String name, Modes mode, String display, String type, String msg, String uri, int max, int min) {
    this(shield, name, mode, display, type, msg, uri, max, min, shield != null ? shield.logger : null, false, Integer.MAX_VALUE, Integer.MIN_VALUE, "", null, null);
  }

  /**
   * Full constructor with all configuration fields.
   *
   * @param shield        owning shield, or {@code null}
   * @param name          parameter name
   * @param mode          validation mode
   * @param display       display name
   * @param type          type string
   * @param msg           custom error message
   * @param uri           URI restriction string
   * @param max           maximum character length
   * @param min           minimum character length
   * @param logger        logger instance
   * @param required      whether a value is required
   * @param maxValue      maximum numeric value
   * @param minValue      minimum numeric value
   * @param maskError     error masking string
   * @param related       raw related-field expression
   * @param relatedBlocks parsed related-field blocks
   */
  ItemData(Shield shield, String name, Modes mode, String display, String type, String msg, String uri, int max, int min, Logger logger, boolean required, double maxValue, double minValue,
      String maskError, String related, RelationValidator.Block[] relatedBlocks) {
    this.name = name;
    this.display = display;
    this.shield = shield;
    this.type = type;
    this.min = min;
    this.max = max;
    this.msg = msg;
    this.uri = uri;
    this.mode = mode;
    this.logger = logger;
    this.required = required;
    this.maxValue = maxValue;
    this.minValue = minValue;
    this.maskError = maskError;
    this.related = related;
    this.relatedBlocks = relatedBlocks;
  }
}
