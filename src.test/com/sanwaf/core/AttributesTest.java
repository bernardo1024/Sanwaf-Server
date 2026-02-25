package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

public class AttributesTest
{
  static Sanwaf sanwaf;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-modes.xml");
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
    Sanwaf.SanwafConfig cfg = sanwaf.config;
    onErrorAddParmDetections = cfg.onErrorAddParmDetections;
    onErrorAddParmErrors = cfg.onErrorAddParmErrors;
    onErrorAddTrackId = cfg.onErrorAddTrackId;
    onErrorLogParmDetections = cfg.onErrorLogParmDetections;
    onErrorLogParmDetectionsVerbose = cfg.onErrorLogParmDetectionsVerbose;
    onErrorLogParmErrors = cfg.onErrorLogParmErrors;
    onErrorLogParmErrorsVerbose = cfg.onErrorLogParmErrorsVerbose;
    sanwaf.config = cfg
        .withOnErrorAddParmDetections(b)
        .withOnErrorAddParmErrors(b)
        .withOnErrorAddTrackId(b)
        .withOnErrorLogParmDetections(b)
        .withOnErrorLogParmDetectionsVerbose(b)
        .withOnErrorLogParmErrors(b)
        .withOnErrorLogParmErrorsVerbose(b);
  }

  private static void resetSanwafAtts()
  {
    Sanwaf.SanwafConfig cfg = sanwaf.config;
    sanwaf.config = cfg
        .withOnErrorAddParmDetections(onErrorAddParmDetections)
        .withOnErrorAddParmErrors(onErrorAddParmErrors)
        .withOnErrorAddTrackId(onErrorAddTrackId)
        .withOnErrorLogParmDetections(onErrorLogParmDetections)
        .withOnErrorLogParmDetectionsVerbose(onErrorLogParmDetectionsVerbose)
        .withOnErrorLogParmErrors(onErrorLogParmErrors)
        .withOnErrorLogParmErrorsVerbose(onErrorLogParmErrorsVerbose);
  }

}

