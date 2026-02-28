package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class StringRegexMixedBlockDetectTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeAll
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-stringRegexMixedBlockDetect.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    }
    catch (IOException ioe)
    {
      fail();
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
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("string", "DETECT_ALL");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testAllStringDetectsRun()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("string", "DETECT_ALL DETECT DETECT_ALL DETECT BLOCK");
    assertTrue(sanwaf.isThreatDetected(request));

  }

  @Test
  public void testAllStringDetectsRun2()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("string", "DETECT_ALL DETECT DETECT_ALL DETECT");
    assertFalse(sanwaf.isThreatDetected(request));

  }

}

