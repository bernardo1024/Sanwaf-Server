package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates input values against a regular-expression {@link Rule}.
 *
 * <p>Two modes are supported:
 * <ul>
 *   <li><b>Named regex</b> ({@code r{patternName}}) - references a rule
 *       defined in the shield's {@code customRulePatterns} or
 *       {@code customRulePatternsDetect} maps. The rule is resolved lazily
 *       on first use.</li>
 *   <li><b>Inline regex</b> ({@code x{pattern}}) - compiles the pattern
 *       directly at construction time with case-insensitive matching.
 *       The compiled rule uses "pass" semantics (fail when no match).</li>
 * </ul>
 *
 * <p>Whether a match indicates an error depends on the rule's
 * {@code failOnMatch} flag: when {@code true}, a regex match means the
 * value is invalid; when {@code false}, the absence of a match means
 * the value is invalid.
 */
final class ItemRegex extends Item {
  /** Default error message prefix for regex validation failures. */
  static final String FAILED_CUSTOM_PATTERN = "Failed Custom Pattern: ";
  /** The rule name (for named regex) or a descriptive label (for inline). */
  final String patternName;
  /** A truncated copy of the type string (max 100 chars) for diagnostics. */
  final String patternString;
  /** {@code true} if the regex was specified inline rather than by name. */
  final boolean isInline;
  /** The compiled rule; lazily resolved for named patterns. */
  volatile Rule rule = null;

  /**
   * Constructs a regex item. For inline patterns the rule is compiled
   * immediately; for named patterns the rule reference is deferred until
   * {@link #resolveRule(Shield)} is called.
   *
   * @param id item configuration data containing the regex type string
   */
  ItemRegex(ItemData id) {
    super(id);
    String value = id.type;
    this.patternString = value.length() > 100 ? value.substring(0, 100) : value;

    String pn = null;
    boolean il = false;
    if (value.startsWith(ItemFactory.INLINE_REGEX)) {
      il = true;
      Pattern inlinePattern = Pattern.compile(value.substring(ItemFactory.INLINE_REGEX.length(), value.length() - 1), Pattern.CASE_INSENSITIVE);
      rule = new Rule(id.mode, inlinePattern, "pass", null);
      pn = "inline-regex: " + rule.pattern;
    } else {
      int start = value.indexOf(ItemFactory.REGEX);
      if (start >= 0) {
        pn = value.substring(start + ItemFactory.REGEX.length(), value.length() - 1);
      }
    }
    this.patternName = pn;
    this.isInline = il;
  }

  /**
   * Returns the compiled rule, lazily resolving it from the shield's
   * custom-rule maps if not already set (i.e., for named patterns).
   *
   * @param shield the shield containing custom rule definitions
   * @return the resolved rule, or {@code null} if the name is not found
   */
  private Rule resolveRule(Shield shield) {
    Rule r = this.rule;
    if (r != null) {
      return r;
    }
    if (shield == null) {
      return null;
    }
    r = shield.customRulePatterns.get(patternName);
    if (r == null) {
      r = shield.customRulePatternsDetect.get(patternName);
    }
    this.rule = r;
    return r;
  }

  /**
   * Returns error highlight points for the value based on the regex rule.
   * When the rule indicates an error, the entire value is highlighted.
   *
   * @param shield the active shield (used to resolve the rule)
   * @param value  the input value being validated
   * @return a single-element list covering the full value on error,
   *         or an empty list otherwise
   */
  @Override
  List<Point> getErrorPoints(final Shield shield, final String value) {
    if (value == null || value.isEmpty() || !maskError.isEmpty()) {
      return Collections.emptyList();
    }
    Rule r = resolveRule(shield);
    if (r == null || r.pattern == null) {
      return Collections.emptyList();
    }
    Matcher m = r.matcher(value);
    boolean found = m.find();
    if ((found && r.failOnMatch) || (!found && !r.failOnMatch)) {
      return Collections.singletonList(new Point(0, value.length()));
    }
    return Collections.emptyList();
  }

  /**
   * Validates the input value against the regex rule.
   *
   * <p>Returns {@code false} (no error) if the rule cannot be resolved,
   * the rule is disabled, the value is empty, or the rule has no pattern.
   * When a violation is detected, the rule's mode determines behavior:
   * detect-only rules log and return {@code false}; block-mode rules
   * return {@code true}.
   *
   * @param req         the servlet request
   * @param shield      the active shield (used to resolve named rules)
   * @param value       the input value to validate
   * @param doAllBlocks whether to process all detection blocks
   * @param log         whether to log violations
   * @return {@code true} if the value violates the rule and the mode is BLOCK
   */
  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log) {
    if (hasPreValidationError(req, value)) {
      return true;
    }
    Rule r = resolveRule(shield);
    if (r == null) {
      if (logger != null && logger.isWarnEnabled()) {
        logger.warn("Pattern not found: " + patternName);
      }
      return false;
    }
    if (r.mode == Modes.DISABLED) {
      return false;
    }
    if (value.isEmpty()) {
      return false;
    }
    if (r.pattern == null) {
      return false;
    }
    boolean match = r.matcher(value).find();
    if ((r.failOnMatch && match) || (!r.failOnMatch && !match)) {
      handleMode(value, req, r.mode, log);
      return r.mode == Modes.BLOCK && mode == Modes.BLOCK;
    }
    return false;
  }

  /** {@inheritDoc} */
  @Override
  String getDefaultErrorMessage() {
    return FAILED_CUSTOM_PATTERN;
  }

  /**
   * Returns a JSON fragment with the regex pattern string.
   *
   * @return JSON key-value pair with the pattern (or the truncated type string
   *         if the rule is not yet resolved)
   */
  @Override
  String getProperties() {
    if (rule != null && rule.pattern != null) {
      return "\"regex\":\"" + JsonFormatter.jsonEncode(rule.pattern.toString()) + "\"";
    } else {
      return "\"regex\":\"" + JsonFormatter.jsonEncode(patternString) + "\"";
    }
  }

  /**
   * Returns {@link Types#INLINE_REGEX} or {@link Types#REGEX} depending
   * on whether the pattern was specified inline.
   *
   * @return the item type
   */
  @Override
  Types getType() {
    if (isInline) {
      return Types.INLINE_REGEX;
    }
    return Types.REGEX;
  }
}
