package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;

/**
 * Validation item for general string parameters with regex-based threat
 * detection.
 *
 * <p>Scans parameter values against the shield's compiled regex rule
 * patterns to detect XSS, injection, and other malicious content. Each
 * {@link Rule} carries a compiled pattern and a mode (BLOCK, DETECT, or
 * DETECT_ALL) that determines whether a match causes rejection, logging,
 * or both.
 *
 * <p>Two optimisations may short-circuit scanning:
 * <ul>
 *   <li>If the value is shorter than {@link Shield#regexMinLen}, it cannot
 *       match any pattern and is accepted immediately.</li>
 *   <li>If {@link Shield#canSkipByCharScan} is enabled and the value
 *       contains no XSS-relevant characters, scanning is skipped.</li>
 * </ul>
 *
 * <p>A shared {@link #DEFAULT_INSTANCE} is used when no per-parameter
 * configuration exists but the shield still needs to apply its global
 * string-pattern rules.
 */
final class ItemString extends Item {
  /** Shared stateless instance used for default string validation. */
  static final ItemString DEFAULT_INSTANCE = new ItemString();
  /** Default error message prefix for pattern-match failures. */
  static final String FAILED_PATTERN = "Failed Pattern: ";

  /**
   * No-arg constructor for the shared {@link #DEFAULT_INSTANCE}.
   */
  ItemString() {
  }

  /**
   * Constructs a string validation item from parsed configuration data.
   *
   * @param id item configuration holder
   */
  ItemString(ItemData id) {
    super(id);
  }

  /**
   * Identifies character ranges in the value that match the shield's
   * block-mode regex patterns.
   *
   * <p>Iterates over {@link Shield#rulePatternsArray} and collects every
   * regex match region as a {@link Point}. Returns an empty list when the
   * shield is {@code null} or error masking is active.
   *
   * @param shield the active shield whose regex patterns are applied
   * @param value  the raw parameter value to scan
   * @return list of {@link Point} ranges marking matched regions, or an
   *         empty list if no patterns match
   */
  @Override
  List<Point> getErrorPoints(final Shield shield, final String value) {
    if (shield == null || !maskError.isEmpty()) {
      return Collections.emptyList();
    }
    List<Point> points = null;
    Rule[] rules = shield.rulePatternsArray;
    for (Rule r : rules) {
      if (r.pattern == null) {
        continue;
      }
      Matcher m = r.matcher(value);
      while (m.find()) {
        if (points == null) {
          points = new ArrayList<>();
        }
        points.add(new Point(m.start(), m.end()));
      }
    }
    return points != null ? points : Collections.emptyList();
  }

  /**
   * Validates the parameter value against the shield's regex rule patterns.
   *
   * <p>Processing order:
   * <ol>
   *   <li>Pre-validation checks (disabled mode, URI filter, size).</li>
   *   <li>Short-circuit if the value is shorter than
   *       {@link Shield#regexMinLen}.</li>
   *   <li>Short-circuit if the value contains no XSS-relevant characters
   *       and {@link Shield#canSkipByCharScan} is enabled.</li>
   *   <li>Run detect-mode patterns ({@link Shield#rulePatternsDetectArray})
   *       for logging/detection purposes; their results do not block.</li>
   *   <li>Run block-mode patterns ({@link Shield#rulePatternsArray});
   *       a match causes the value to be rejected.</li>
   * </ol>
   *
   * <p>If the item's own mode is DETECT or DETECT_ALL, the method always
   * returns {@code false} (the value is never blocked, only logged).
   *
   * @param req         the current servlet request
   * @param shield      the active shield configuration
   * @param value       the parameter value to validate
   * @param doAllBlocks {@code true} to evaluate all block-mode rules
   *                    instead of stopping at the first match
   * @param log         {@code true} to log validation failures
   * @return {@code true} if the value matches a blocking pattern and the
   *         item is not in detect-only mode
   */
  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log) {
    if (hasPreValidationError(req, value)) {
      return true;
    }
    boolean inError = false;
    if (shield != null) {
      if (value.length() < shield.regexMinLen) {
        return false;
      }
      if (shield.canSkipByCharScan && Shield.containsNoXssRelevantChar(value)) {
        return false;
      }
      // first process the detects & detect all - ignore the return value for detect
      // skip when item is BLOCK and caller wants fast-fail (doAllBlocks=false)
      if (shield.rulePatternsDetectArray.length > 0 && (doAllBlocks || mode == Modes.DETECT || mode == Modes.DETECT_ALL)) {
        isInErrorForPatterns(req, shield.rulePatternsDetectArray, value, doAllBlocks);
      }
      // then do the blocks
      inError = isInErrorForPatterns(req, shield.rulePatternsArray, value, doAllBlocks);
    }
    if (mode == Modes.DETECT || mode == Modes.DETECT_ALL) {
      return false;
    }
    return inError;
  }

  /**
   * Evaluates a set of regex rules against the value.
   *
   * <p>For each enabled rule, the value is matched against the rule's
   * compiled pattern. A rule triggers when its match result aligns with
   * its {@link Rule#failOnMatch} flag (match-and-fail-on-match, or
   * no-match-and-not-fail-on-match).
   *
   * <p>When a rule triggers:
   * <ul>
   *   <li>BLOCK rules set the error flag and invoke
   *       {@link #handleMode} with match points.</li>
   *   <li>DETECT / DETECT_ALL rules invoke {@link #handleMode} for
   *       logging only.</li>
   * </ul>
   *
   * <p>Iteration stops at the first trigger unless the item or rule is in
   * DETECT_ALL mode, or {@code doAllBlocks} is {@code true}.
   *
   * @param req         the current servlet request
   * @param rules       array of rules to evaluate
   * @param value       the parameter value to test
   * @param doAllBlocks {@code true} to continue past the first block match
   * @return {@code true} if at least one BLOCK-mode rule was triggered
   */
  private boolean isInErrorForPatterns(final ServletRequest req, Rule[] rules, final String value, boolean doAllBlocks) {
    boolean inError = false;
    for (Rule r : rules) {
      Modes ruleMode = r.mode;
      if (ruleMode != Modes.DISABLED) {
        if (r.pattern == null) {
          continue;
        }
        Matcher m = r.matcher(value);
        boolean match = m.find();
        if ((r.failOnMatch && match) || (!r.failOnMatch && !match)) {
          List<Point> points = match ? collectMatchPoints(m) : null;
          if (r.mode == Modes.BLOCK) {
            inError = true;
            handleMode(value, req, ruleMode, true, doAllBlocks, null, points);
          } else {
            handleMode(value, req, ruleMode, true, points);
          }
          if (doAllBlocks || (mode != Modes.DETECT_ALL && ruleMode != Modes.DETECT_ALL)) {
            break;
          }
        }
      }
    }
    return inError;
  }

  /**
   * Collects all remaining match regions from an already-matched
   * {@link Matcher} into a list of {@link Point} ranges.
   *
   * <p>The matcher must have already found at least one match (via
   * {@code find()}) before this method is called; it consumes the
   * current match and any subsequent matches.
   *
   * @param m a matcher that has already found at least one match
   * @return list of {@link Point} ranges for all matched regions
   */
  private static List<Point> collectMatchPoints(Matcher m) {
    List<Point> points = new ArrayList<>();
    do {
      points.add(new Point(m.start(), m.end()));
    } while (m.find());
    return points;
  }

  /**
   * Returns the default error message prefix for pattern-match failures.
   *
   * @return {@value #FAILED_PATTERN}
   */
  @Override
  String getDefaultErrorMessage() {
    return FAILED_PATTERN;
  }

  /**
   * Returns the item type identifier.
   *
   * @return {@link Types#STRING}
   */
  @Override
  Types getType() {
    return Types.STRING;
  }
}
