package com.sanwaf.log;

//DO NOT USE THIS CLASS IN PRODUCTION
public final class SimpleLogger implements Logger
{
  private static final java.util.logging.Logger LOGGER = java.util.logging.Logger.getLogger(SimpleLogger.class.getName());

  @Override
  public void error(String s)
  {
    LOGGER.log(java.util.logging.Level.SEVERE, "Sanwaf-error:\t{0}", s);
  }

  @Override
  public void warn(String s)
  {
    LOGGER.log(java.util.logging.Level.WARNING, "Sanwaf-warn:\t{0}", s);
  }

  @Override
  public void info(String s)
  {
    LOGGER.log(java.util.logging.Level.INFO, "Sanwaf-info:\t{0}", s);
  }

  @Override
  public boolean isErrorEnabled()
  {
    return LOGGER.isLoggable(java.util.logging.Level.SEVERE);
  }

  @Override
  public boolean isWarnEnabled()
  {
    return LOGGER.isLoggable(java.util.logging.Level.WARNING);
  }

  @Override
  public boolean isInfoEnabled()
  {
    return LOGGER.isLoggable(java.util.logging.Level.INFO);
  }
}
