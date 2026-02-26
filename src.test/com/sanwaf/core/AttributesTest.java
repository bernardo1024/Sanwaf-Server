package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

public class AttributesTest
{
  static Sanwaf sanwaf;

  @BeforeAll
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
    setSanwafAttributes(true);
    request.addParameter("regexParmNoModeWithRegexDetectMode", "AAAAAAA");
    request.addParameter("regexParmNoModeWithRegexDetectMode", "BBBBBBB");
    request.addParameter("numericdelimited", "aaaaaaaaaa");
    request.addParameter("numericdelimited", "bbbbbbbbbb");
    boolean threat = sanwaf.isThreatDetected(request);
    assertFalse(threat);
    resetSanwafAttributes();
  }

  @Test
  public void testAttributesAllOff()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    setSanwafAttributes(false);
    request.addParameter("regexParmNoModeWithRegexDetectMode", "AAAAAAA");
    request.addParameter("regexParmNoModeWithRegexDetectMode", "BBBBBBB");
    request.addParameter("numericdelimited", "aaaaaaaaaa");
    request.addParameter("numericdelimited", "bbbbbbbbbb");
    boolean threat = sanwaf.isThreatDetected(request);
    assertFalse(threat);
    resetSanwafAttributes();
  }

  static Sanwaf.SanwafConfig savedConfig;

  private void setSanwafAttributes(boolean b)
  {
    savedConfig = sanwaf.config;
    sanwaf.config = savedConfig.toBuilder()
        .onErrorAddParmDetections(b)
        .onErrorAddParmErrors(b)
        .onErrorAddTrackId(b)
        .onErrorLogParmDetections(b)
        .onErrorLogParmDetectionsVerbose(b)
        .onErrorLogParmErrors(b)
        .onErrorLogParmErrorsVerbose(b)
        .build();
  }

  private static void resetSanwafAttributes()
  {
    sanwaf.config = savedConfig;
  }

}

