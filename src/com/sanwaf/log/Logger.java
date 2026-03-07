package com.sanwaf.log;

public interface Logger {
  void error(String s);

  void warn(String s);

  void info(String s);

  default boolean isErrorEnabled() {
    return true;
  }

  default boolean isWarnEnabled() {
    return true;
  }

  default boolean isInfoEnabled() {
    return true;
  }
}
