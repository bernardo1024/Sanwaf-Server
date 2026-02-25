package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class AaSimpleTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-AaSimpleTest.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testEndpointDetectAll()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/sanwaf-AaSimpleTest.xml");
    request.addParameter("estring_DETECT_ALL", "sDETECTALL");
    assertFalse(sanwaf.isThreatDetected(request, true, true));
    String s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_DETECT_ALL\""));
    assertEquals(1, GetAllErrorsTest.getItemCount(s, "\"item\":{\"name\":\""));
  }

}

