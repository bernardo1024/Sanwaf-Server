package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class AlwaysPerformRegexTest
{
  static Sanwaf sanwaf;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-verboseRegexAlways.xml");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testRegexAlways()
  {
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

