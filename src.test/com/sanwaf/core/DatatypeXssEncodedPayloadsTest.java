package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.fail;

public class DatatypeXssEncodedPayloadsTest {
  static Sanwaf sanwaf;
  static Shield shield;

  static final int iterations = 1;
  static final boolean doHex = false;
  static final boolean logErrors = true;

  @BeforeAll
  public static void setUpClass() {
    try {
      sanwaf = new Sanwaf();
      shield = UnitTestUtil.getShield(sanwaf, "XSS");
    } catch (IOException ioe) {
      fail();
    }
  }

  @Test
  public void XssFormElementsEncoded() {
    UnitTestResult result = UnitTestUtil.runTestsUsingFile(shield, "src.test/resources/xssFormEncodedPayloads.txt", iterations, doHex, logErrors);
    UnitTestUtil.log("XSS-SanWaf", result);
  }
}
