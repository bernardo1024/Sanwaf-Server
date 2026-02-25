package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class AttributesTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-modes.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testAttributesAllOn()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    setSanwafAtts(true);
    request.addParameter("regexParmNoModeWithRegexDetectMode", "AAAAAAA");
    request.addParameter("regexParmNoModeWithRegexDetectMode", "BBBBBBB");
    request.addParameter("numericdelimited", "aaaaaaaaaa");
    request.addParameter("numericdelimited", "bbbbbbbbbb");
    boolean threat = sanwaf.isThreatDetected(request);
    assertFalse(threat);
    resetSanwafAtts();
  }

  @Test
  public void testAttributesAllOff()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    setSanwafAtts(false);
    request.addParameter("regexParmNoModeWithRegexDetectMode", "AAAAAAA");
    request.addParameter("regexParmNoModeWithRegexDetectMode", "BBBBBBB");
    request.addParameter("numericdelimited", "aaaaaaaaaa");
    request.addParameter("numericdelimited", "bbbbbbbbbb");
    boolean threat = sanwaf.isThreatDetected(request);
    assertFalse(threat);
    resetSanwafAtts();
  }

  static boolean onErrorAddParmDetections = false;
  static boolean onErrorAddParmErrors = false;
  static boolean onErrorAddTrackId = false;
  static boolean onErrorLogParmDetections = false;
  static boolean onErrorLogParmDetectionsVerbose = false;
  static boolean onErrorLogParmErrors = false;
  static boolean onErrorLogParmErrorsVerbose = false;

  private void setSanwafAtts(boolean b)
  {
    onErrorAddParmDetections = sanwaf.onErrorAddParmDetections;
    onErrorAddParmErrors = sanwaf.onErrorAddParmErrors;
    onErrorAddTrackId = sanwaf.onErrorAddTrackId;
    onErrorLogParmDetections = sanwaf.onErrorLogParmDetections;
    onErrorLogParmDetectionsVerbose = sanwaf.onErrorLogParmDetectionsVerbose;
    onErrorLogParmErrors = sanwaf.onErrorLogParmErrors;
    onErrorLogParmErrorsVerbose = sanwaf.onErrorLogParmErrorsVerbose;
    sanwaf.onErrorAddParmDetections = b;
    sanwaf.onErrorAddParmErrors = b;
    sanwaf.onErrorAddTrackId = b;
    sanwaf.onErrorLogParmDetections = b;
    sanwaf.onErrorLogParmDetectionsVerbose = b;
    sanwaf.onErrorLogParmErrors = b;
    sanwaf.onErrorLogParmErrorsVerbose = b;
  }

  private static void resetSanwafAtts()
  {
    sanwaf.onErrorAddParmDetections = onErrorAddParmDetections;
    sanwaf.onErrorAddParmErrors = onErrorAddParmErrors;
    sanwaf.onErrorAddTrackId = onErrorAddTrackId;
    sanwaf.onErrorLogParmDetections = onErrorLogParmDetections;
    sanwaf.onErrorLogParmDetectionsVerbose = onErrorLogParmDetectionsVerbose;
    sanwaf.onErrorLogParmErrors = onErrorLogParmErrors;
    sanwaf.onErrorLogParmErrorsVerbose = onErrorLogParmErrorsVerbose;
  }

}

