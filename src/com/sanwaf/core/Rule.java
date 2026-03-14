package com.sanwaf.core;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A compiled detection rule used by the regex-based scanner.
 *
 * <p>Each rule pairs a compiled {@link Pattern} with metadata that determines
 * the operational {@link Modes mode}, whether a match indicates a threat
 * ({@code failOnMatch}), and an optional error message. A {@link ThreadLocal}
 * {@link Matcher} is cached per rule to avoid repeated allocation on the hot
 * path.
 */
class Rule {
  /** Operational mode governing how a match against this rule is handled. */
  final Modes mode;
  /** Compiled regex pattern for this rule. */
  final Pattern pattern;
  /** {@code true} if a regex match means the value is invalid (fail-on-match). */
  final boolean failOnMatch;
  /** Optional error message associated with this rule. */
  final String msg;
  private final ThreadLocal<Matcher> cachedMatcher;

  /**
   * Constructs a new rule.
   *
   * @param mode    the operational mode for this rule
   * @param pattern the compiled regex pattern ({@code null} permitted but unusual)
   * @param match   {@code "pass"} if a regex match means the value is valid;
   *                any other value means a match indicates a threat
   * @param msg     optional error message; may be {@code null}
   */
  Rule(Modes mode, Pattern pattern, String match, String msg) {
    this.mode = mode;
    this.pattern = pattern;
    this.failOnMatch = !"pass".equalsIgnoreCase(match);
    this.msg = msg;
    this.cachedMatcher = pattern != null ? ThreadLocal.withInitial(() -> pattern.matcher("")) : null;
  }

  /**
   * Returns a thread-local {@link Matcher} reset to the given value.
   *
   * @param value the string to match against
   * @return a {@link Matcher} ready for use on the current thread
   */
  Matcher matcher(String value) {
    return cachedMatcher.get().reset(value);
  }
}
