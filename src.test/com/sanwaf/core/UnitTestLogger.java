package com.sanwaf.core;

import com.sanwaf.log.Logger;

public class UnitTestLogger implements Logger {

  @Override
  public void error(String s) {
    System.out.println(s);
  }

  @Override
  public void warn(String s) {
    System.out.println(s);
  }

  @Override
  public void info(String s) {
    System.out.println(s);
  }
}
