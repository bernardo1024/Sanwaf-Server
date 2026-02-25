package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ReduceXmlTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-reduced.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void numericTest()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("Numeric", "abc123");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);

    request = new MockHttpServletRequest();
    request.addParameter("Numeric", "12345");
    result = sanwaf.isThreatDetected(request);
    assertFalse(result);
  }
}

