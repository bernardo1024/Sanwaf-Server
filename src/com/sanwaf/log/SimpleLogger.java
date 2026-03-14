package com.sanwaf.log;

/**
 * Default {@link Logger} implementation backed by {@link java.util.logging}.
 *
 * <p>This logger is provided for development and testing convenience.
 * <strong>Do not use in production</strong> — supply an application-specific
 * {@link Logger} implementation instead.
 */
public final class SimpleLogger implements Logger {
  private static final java.util.logging.Logger LOGGER = java.util.logging.Logger.getLogger(SimpleLogger.class.getName());

  /** {@inheritDoc} */
  @Override
  public void error(String s) {
    LOGGER.log(java.util.logging.Level.SEVERE, "Sanwaf-error:\t{0}", s);
  }

  /** {@inheritDoc} */
  @Override
  public void warn(String s) {
    LOGGER.log(java.util.logging.Level.WARNING, "Sanwaf-warn:\t{0}", s);
  }

  /** {@inheritDoc} */
  @Override
  public void info(String s) {
    LOGGER.log(java.util.logging.Level.INFO, "Sanwaf-info:\t{0}", s);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isErrorEnabled() {
    return LOGGER.isLoggable(java.util.logging.Level.SEVERE);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isWarnEnabled() {
    return LOGGER.isLoggable(java.util.logging.Level.WARNING);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isInfoEnabled() {
    return LOGGER.isLoggable(java.util.logging.Level.INFO);
  }
}
