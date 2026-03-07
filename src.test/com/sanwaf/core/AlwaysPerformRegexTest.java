package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class AlwaysPerformRegexTest {
  static Sanwaf sanwaf;

  @BeforeAll
  public static void setUpClass() {
    try {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-verboseRegexAlways.xml");
    } catch (IOException ioe) {
      fail();
    }
  }

  @Test
  public void testRegexAlways() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("StringExcluded", "<script>alert(1)</script>");
    boolean result = sanwaf.isThreatDetected(request);
    assertFalse(result);

    request = new MockHttpServletRequest();
    request.addParameter("foobar", "<script>alert(1)</script>");
    result = sanwaf.isThreatDetected(request);
    assertTrue(result);
  }
}
