package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertTrue;

public class StringRegexMixedBlockDetectTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-stringRegexMixedBlockDetect.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    }
    catch (IOException ioe)
    {
      assertTrue(false);
    }
  }

  @Test
  public void testParmsRun()
  {
    //<item><mode>block</mode><name>modeParameter-BLOCK</name><type>s</type></item>
    //<item><mode>detect</mode><name>modeParameter-DETECT</name><type>s</type></item>
    //<item><mode>detect-all</mode><name>modeParameter-DETECT_ALL</name><type>s</type></item>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("string", "BLOCK");
    assertTrue(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("string", "DETECT");
    assertTrue(!sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("string", "DETECT_ALL");
    assertTrue(!sanwaf.isThreatDetected(request));
  }

  @Test
  public void testAllStringDetectsRun()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.addParameter("string", "DETECT_ALL DETECT DETECT_ALL DETECT BLOCK");
    assertTrue(sanwaf.isThreatDetected(request));

  }

  @Test
  public void testAllStringDetectsRun2()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.addParameter("string", "DETECT_ALL DETECT DETECT_ALL DETECT");
    assertTrue(!sanwaf.isThreatDetected(request));

  }

}

