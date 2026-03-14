package com.sanwaf.core;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Abstract base class for all Sanwaf validation item types.
 *
 * <p>Each concrete subclass (e.g. {@code ItemNumeric}, {@code ItemString},
 * {@code ItemRegex}) implements type-specific validation logic via the
 * {@link #inError}, {@link #getErrorPoints}, and {@link #getType} template
 * methods. Common behaviour such as size checking, URI filtering, mode
 * handling, and related-field validation lives here in the base class.
 *
 * <p>Instances are created by {@link ItemFactory#getNewItem(ItemData)}.
 */
abstract class Item {
  /** Logger used for recording validation errors and detections. */
  com.sanwaf.log.Logger logger;
  /** Parameter name this item validates. */
  String name;
  /** Human-readable display name used in error messages. */
  String display;
  /** Shield that owns this item. */
  Shield shield;
  /** Maximum allowed character length of the parameter value. */
  int max = Integer.MAX_VALUE;
  /** Minimum allowed character length of the parameter value. */
  int min = 0;
  /** Maximum allowed numeric value (for numeric types). */
  double maxValue;
  /** Minimum allowed numeric value (for numeric types). */
  double minValue;
  /** Custom error message; {@code null} to use the shield-level default. */
  String msg = null;
  /** Set of URI paths this item applies to; {@code null} means all URIs. */
  Set<String> uriSet = null;
  /** Validation mode (BLOCK, DETECT, or DISABLED). */
  Modes mode = Modes.BLOCK;
  /** Whether a non-empty value is required. */
  boolean required = false;
  /** Raw related-field validation expression. */
  String related;
  /** Parsed related-field validation blocks. */
  RelationValidator.Block[] relatedBlocks;
  /** Mask applied to the parameter value in error output. */
  String maskError = "";

  /**
   * Default no-arg constructor for subclass use.
   */
  Item() {
  }

  /**
   * Constructs an item from parsed configuration data.
   *
   * @param id item configuration holder
   */
  Item(ItemData id) {
    name = id.name;
    mode = id.mode;
    shield = id.shield;
    logger = id.logger;

    if (id.display.isEmpty()) {
      display = name;
    } else {
      display = id.display;
    }
    max = id.max;
    min = id.min;
    msg = id.msg;
    setUri(id.uri);
    required = id.required;
    maxValue = id.maxValue;
    minValue = id.minValue;
    maskError = id.maskError;
    related = id.related;
    relatedBlocks = id.relatedBlocks;
  }

  /**
   * Validates a parameter value according to this item's type rules.
   *
   * @param req         the servlet request
   * @param shield      the shield performing the validation
   * @param value       the parameter value to validate
   * @param doAllBlocks {@code true} to evaluate all blocks (for error-point
   *                    collection), {@code false} to fail fast
   * @param log         {@code true} to log errors/detections
   * @return {@code true} if the value is invalid
   */
  abstract boolean inError(ServletRequest req, Shield shield, String value, boolean doAllBlocks, boolean log);

  /**
   * Returns the character-level error points within the given value.
   *
   * @param shield the shield performing the validation
   * @param value  the parameter value to inspect
   * @return list of {@link Point} instances identifying error positions,
   *         or an empty list if none
   */
  abstract List<Point> getErrorPoints(Shield shield, String value);

  /**
   * Returns the {@link Types} enum constant for this item subclass.
   *
   * @return the validation type
   */
  abstract Types getType();

  /**
   * Checks pre-validation conditions that short-circuit type-specific logic.
   *
   * <p>Returns {@code true} (skip further validation) when the item is
   * disabled, the request URI does not match, or the value violates
   * size constraints.
   *
   * @param req   the servlet request
   * @param value the parameter value
   * @return {@code true} if a pre-validation condition is met
   */
  boolean hasPreValidationError(ServletRequest req, String value) {
    return mode == Modes.DISABLED || isUriInvalid(req) || isSizeError(value);
  }

  /**
   * Checks whether the request URI is outside this item's allowed URI set.
   *
   * @param req the servlet request
   * @return {@code true} if the request URI is not in the allowed set,
   *         {@code false} if no URI restriction is configured or the URI matches
   */
  boolean isUriInvalid(ServletRequest req) {
    if (uriSet == null || req == null) {
      return false;
    }
    String reqUri = ((HttpServletRequest) req).getRequestURI();
    return !uriSet.contains(reqUri);
  }

  /**
   * Checks whether the value length violates min/max constraints.
   *
   * <p>Empty or {@code null} values are allowed when {@link #required} is
   * {@code false}; otherwise a {@code null} value is always an error.
   *
   * @param value the parameter value
   * @return {@code true} if the value length is out of bounds
   */
  boolean isSizeError(String value) {
    if (!required && (value == null || value.isEmpty())) {
      return false;
    }
    if (value == null) {
      return true;
    }
    return (value.length() < min || value.length() > max);
  }

  /**
   * Hook for subclasses to customise the error message before it is returned.
   *
   * <p>The default implementation returns the message unchanged.
   *
   * @param req      the servlet request
   * @param errorMsg the original error message
   * @return the (possibly modified) error message
   */
  String modifyErrorMsg(ServletRequest req, String errorMsg) {
    return errorMsg;
  }

  /**
   * Replaces the first {@code {0}} placeholder in an error message.
   *
   * @param errorMsg    the error message template
   * @param replacement the value to substitute for the placeholder
   * @return the message with the placeholder replaced, or the original message
   *         if no placeholder is found
   */
  static String replacePlaceholder(String errorMsg, String replacement) {
    int i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER1);
    if (i >= 0) {
      int pLen = ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length();
      return errorMsg.substring(0, i) + replacement + errorMsg.substring(i + pLen);
    }
    return errorMsg;
  }

  /**
   * Parses a separator-delimited URI string and populates {@link #uriSet}.
   *
   * @param uriString the raw URI string from configuration, or {@code null}
   */
  private void setUri(String uriString) {
    if (uriString != null && !uriString.isEmpty()) {
      String[] parts = uriString.split(Shield.SEPARATOR);
      uriSet = new HashSet<>(parts.length * 2);
      Collections.addAll(uriSet, parts);
    }
  }

  /**
   * Handles mode-based logging/attribute-setting after a validation failure.
   *
   * <p>Convenience overload that delegates to
   * {@link #handleMode(String, ServletRequest, Modes, boolean, boolean, String, List)}.
   *
   * @param value  the parameter value
   * @param req    the servlet request
   * @param action the current mode (BLOCK, DETECT, or DISABLED)
   * @param log    {@code true} to enable logging
   */
  void handleMode(String value, ServletRequest req, Modes action, boolean log) {
    handleMode(value, req, action, log, false, null, null);
  }

  /**
   * Handles mode-based logging/attribute-setting with error points.
   *
   * @param value       the parameter value
   * @param req         the servlet request
   * @param action      the current mode
   * @param log         {@code true} to enable logging
   * @param errorPoints character-level error positions, or {@code null}
   */
  void handleMode(String value, ServletRequest req, Modes action, boolean log, List<Point> errorPoints) {
    handleMode(value, req, action, log, false, null, errorPoints);
  }

  /**
   * Handles mode-based logging/attribute-setting with related error message.
   *
   * @param value         the parameter value
   * @param req           the servlet request
   * @param action        the current mode
   * @param log           {@code true} to enable logging
   * @param doAllBlocks   {@code true} to evaluate all blocks
   * @param relatedErrMsg related-field validation error message, or {@code null}
   * @return {@code true} if the mode is BLOCK and the request should be blocked
   */
  boolean handleMode(String value, ServletRequest req, Modes action, boolean log, boolean doAllBlocks, String relatedErrMsg) {
    return handleMode(value, req, action, log, doAllBlocks, relatedErrMsg, null);
  }

  /**
   * Core mode handler that logs validation failures and/or sets request
   * attributes depending on the configured {@link Modes mode}.
   *
   * <p>In BLOCK mode the failure is logged as an error and the method returns
   * {@code true} to signal that the request should be rejected. In DETECT mode
   * the failure is logged as a warning and the method returns {@code false}.
   *
   * @param value         the parameter value
   * @param req           the servlet request
   * @param action        the current mode
   * @param log           {@code true} to enable logging
   * @param doAllBlocks   {@code true} to evaluate all blocks
   * @param relatedErrMsg related-field validation error message, or {@code null}
   * @param errorPoints   character-level error positions, or {@code null}
   * @return {@code true} if the mode is BLOCK and the request should be blocked
   */
  boolean handleMode(String value, ServletRequest req, Modes action, boolean log, boolean doAllBlocks, String relatedErrMsg, List<Point> errorPoints) {
    if (Modes.DISABLED == action) {
      return false;
    }
    Sanwaf.SanwafConfig cfg = (shield != null) ? shield.sanwaf.config : null;
    if (Modes.BLOCK == mode) {
      boolean doLog = logger != null && log && !doAllBlocks && (cfg == null || cfg.onErrorLogParmErrors) && logger.isErrorEnabled();
      boolean doAttr = req != null && (cfg == null || cfg.onErrorAddParmErrors);
      if (doLog || doAttr) {
        String json = JsonFormatter.toJson(this, value, mode, req, true, relatedErrMsg, errorPoints);
        if (doLog) {
          logger.error(json);
        }
        if (doAttr) {
          JsonFormatter.appendAttribute(Sanwaf.ATT_LOG_ERROR, json, req);
        }
      }
      return true;
    } else {
      // DETECTS
      boolean doLog = logger != null && log && (cfg == null || cfg.onErrorLogParmDetections) && logger.isWarnEnabled();
      boolean doAttr = req != null && (cfg == null || cfg.onErrorAddParmDetections);
      if (doLog || doAttr) {
        String json = JsonFormatter.toJson(this, value, mode, req, true, relatedErrMsg, errorPoints);
        if (doLog) {
          logger.warn(json);
        }
        if (doAttr) {
          JsonFormatter.appendAttribute(Sanwaf.ATT_LOG_DETECT, json, req);
        }
      }
    }
    return false;
  }

  /**
   * Validates related-field constraints for this item.
   *
   * @param value the parameter value
   * @param req   the servlet request
   * @param meta  metadata context for the validation
   * @return an error message if validation fails, or {@code null} if valid
   */
  String isRelateValid(String value, ServletRequest req, Metadata meta) {
    return RelationValidator.validate(relatedBlocks, related, value, req, meta);
  }

  /**
   * Returns the default error message for this item type.
   *
   * <p>Subclasses typically override this to return a type-specific message
   * from the shield's error-message map.
   *
   * @return the default error message string
   */
  String getDefaultErrorMessage() {
    return "Validation Error";
  }

  /**
   * Returns type-specific properties for JSON serialization.
   *
   * <p>The default implementation returns {@code null}; subclasses override
   * to provide additional detail (e.g. regex pattern, allowed characters).
   *
   * @return a properties string, or {@code null}
   */
  String getProperties() {
    return null;
  }

  /**
   * Returns a JSON representation of this item.
   *
   * @return JSON string describing this item's configuration
   */
  public String toString() {
    return JsonFormatter.toJson(this, null, null, null, true, null, null);
  }
}
