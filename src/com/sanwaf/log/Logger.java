package com.sanwaf.log;

/**
 * Logging abstraction for Sanwaf.
 *
 * <p>Implementations supply the actual logging back-end. Sanwaf calls the
 * level-check methods ({@link #isErrorEnabled()}, {@link #isWarnEnabled()},
 * {@link #isInfoEnabled()}) before building expensive log messages, so
 * implementations should return accurate values.
 *
 * @see SimpleLogger
 */
public interface Logger {
  /**
   * Logs a message at ERROR level.
   *
   * @param s the message to log
   */
  void error(String s);

  /**
   * Logs a message at WARN level.
   *
   * @param s the message to log
   */
  void warn(String s);

  /**
   * Logs a message at INFO level.
   *
   * @param s the message to log
   */
  void info(String s);

  /**
   * Returns whether ERROR-level logging is enabled.
   *
   * @return {@code true} if ERROR messages will be recorded
   */
  default boolean isErrorEnabled() {
    return true;
  }

  /**
   * Returns whether WARN-level logging is enabled.
   *
   * @return {@code true} if WARN messages will be recorded
   */
  default boolean isWarnEnabled() {
    return true;
  }

  /**
   * Returns whether INFO-level logging is enabled.
   *
   * @return {@code true} if INFO messages will be recorded
   */
  default boolean isInfoEnabled() {
    return true;
  }
}
