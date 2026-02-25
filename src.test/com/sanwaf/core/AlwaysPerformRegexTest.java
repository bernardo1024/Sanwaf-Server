package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import static org.junit.Assert.assertTrue;

public class AlwaysPerformRegexTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-verboseRegexAlways.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    }
    catch (IOException ioe)
    {
      assertTrue(false);
    }
  }

  @Test
  public void testRegexAlways()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("StringExcluded", "<script>alert(1)</script>");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(false));

    request = new MockHttpServletRequest();
    request.addParameter("foobar", "<script>alert(1)</script>");
    result = sanwaf.isThreatDetected(request);
    assertTrue(result);
  }
}

