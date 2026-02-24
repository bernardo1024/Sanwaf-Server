package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import static org.junit.Assert.assertTrue;

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
      assertTrue(false);
    }
  }

  @Test
  public void numericTest() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("Numeric", "abc123");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);

    request = new MockHttpServletRequest();
    request.addParameter("Numeric", "12345");
    result = sanwaf.isThreatDetected(request);
    assertTrue(!result);
  }
}

