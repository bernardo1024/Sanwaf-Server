package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class DatatypeXssEncodedPayloadsTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  static int iterations = 1;
  static boolean doHex = false;
  static boolean logErrors = true;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf();
      shield = UnitTestUtil.getShield(sanwaf, "XSS");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void XssFormElementsEncoded()
  {
    UnitTestResult result = UnitTestUtil.runTestsUsingFile(shield, "src.test/resources/xssFormEncodedPayloads.txt", iterations, doHex, logErrors);
    UnitTestUtil.log("XSS-SanWaf", result);
  }
}

