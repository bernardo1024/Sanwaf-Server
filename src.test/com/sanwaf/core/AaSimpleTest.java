package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class AaSimpleTest
{
  static Sanwaf sanwaf;

  @BeforeAll
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-AaSimpleTest.xml");
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
    //noinspection SpellCheckingInspection
    request.addParameter("estring_DETECT_ALL", "sDETECTALL");
    assertFalse(sanwaf.isThreatDetected(request, true, true));
    String s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_DETECT_ALL\""));
    assertEquals(1, GetAllErrorsTest.getItemCount(s, "\"item\":{\"name\":\""));
  }

}

