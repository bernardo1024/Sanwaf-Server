package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertTrue;

public class RegexUsingFilesTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-regexUsingFiles.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    }
    catch (IOException ioe)
    {
      assertTrue(false);
    }
  }

  @Test
  public void testRegex1()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("regex1", "123456");
    assertTrue(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("regex1", "123-456-7890");
    assertTrue(!sanwaf.isThreatDetected(request));
  }

  @Test
  public void testRegex2()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("regex2", "123456");
    assertTrue(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("regex2", "123-456-7890");
    assertTrue(!sanwaf.isThreatDetected(request));
  }

  @Test
  public void testRegexString()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("string", "123-456-7890");
    assertTrue(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("string", "123456");
    assertTrue(!sanwaf.isThreatDetected(request));
  }

}

