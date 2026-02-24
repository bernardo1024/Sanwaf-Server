package com.sanwaf.core;

public class UnitTestResult
{
  long start = 0;
  long end = 0;
  int pass = 0;
  int fail = 0;
  StringBuilder errors = new StringBuilder();

  public void start()
  {
    start = System.nanoTime();
  }

  public void end()
  {
    end = System.nanoTime();
  }

  public final long getTestTime()
  {
    return end - start;
  }

  public long getAvgTime()
  {
    int i = pass + fail;
    if (i > 0)
    {
      return (end - start) / (pass + fail);
    }
    else
    {
      return end - start;
    }
  }
}

