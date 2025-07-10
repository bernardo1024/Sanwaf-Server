package com.sanwaf.core;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

public class AaSimpleTest {
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass() {
    try {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-AaSimpleTest.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    } catch (IOException ioe) {
      assertTrue(false);
    }
  }

  @Test
  public void testEndpointDetectAll() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/sanwaf-AaSimpleTest.xml");
    request.addParameter("estring_DETECT_ALL", "sDETECTALL");
    assertFalse(sanwaf.isThreatDetected(request, true, true));
    String s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_DETECT_ALL\""));
    assertTrue(GetAllErrorsTest.getItemCount(s, "\"item\":{\"name\":\"") == 1);
  }

}

