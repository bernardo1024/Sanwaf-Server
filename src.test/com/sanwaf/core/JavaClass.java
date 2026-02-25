package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

/*
 * To use java class's in Sanwaf:
 *   1. class must be on your classpath
 *   2. method must be declared public static
 *   3. method must have 2 input parameters: String & ServletRequest
 *   4. method returns true for an issue detected; false of no issue
 */
@SuppressWarnings("unused")
public class JavaClass
{
  public static boolean over10TrueElseFalse(String s, ServletRequest req)
  {
    return Integer.parseInt(s) > 10;
  }

  public static boolean multiParmsNotEqual(String s, ServletRequest req)
  {
    String s2 = req.getParameter("JavaMultiParm2");
    String s3 = req.getParameter("JavaMultiParm3");
    return !s.equals(s2) || !s.equals(s3);
  }
}

