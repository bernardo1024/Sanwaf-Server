package com.sanwaf.core;

/**
 * Enumeration of all validation types that Sanwaf supports.
 *
 * <p>Each constant corresponds to a distinct validation strategy applied to
 * incoming request parameter values.
 */
public enum Types {
  /** Whole integer values (no decimals). */
  INTEGER,
  /** Delimited list of integer values. */
  INTEGER_DELIMITED,
  /** Numeric values including decimals. */
  NUMERIC,
  /** Delimited list of numeric values. */
  NUMERIC_DELIMITED,
  /** Alphanumeric characters only (letters and digits). */
  ALPHANUMERIC,
  /** Alphanumeric characters plus a configurable set of extra characters. */
  ALPHANUMERIC_AND_MORE,
  /** Free-form string validated against attack patterns. */
  STRING,
  /** Open type; no validation is performed. */
  OPEN,
  /** Single character value. */
  CHAR,
  /** Value validated against a configured regular expression. */
  REGEX,
  /** Value validated against a regex specified inline in the configuration. */
  INLINE_REGEX,
  /** Value validated by a custom Java class. */
  JAVA,
  /** Value must match one of a fixed set of constants. */
  CONSTANT,
  /** Value must conform to a specified format pattern. */
  FORMAT,
  /** Format validation whose pattern depends on another parameter's value. */
  DEPENDENT_FORMAT,
  /** Strict mode; applied globally when strict parameter checking is enabled. */
  STRICT
}
