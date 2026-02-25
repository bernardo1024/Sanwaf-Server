package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SanwafTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf();
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testXssNoThreat()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("String", "abcdefghij");
    Boolean result = sanwaf.isThreatDetected(request);
    assertFalse(result);
  }

  @Test
  public void testXssWithThreat()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("String", "<script>alert(1);</script>");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);
  }

  @Test
  public void testTrackIdAndGetErrorsNumbersDelimited()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.addParameter("NumericDelimited", "+foobar");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);

    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    String s = Sanwaf.getErrors(request);
    assertTrue(s.contains("{\"name\":\"NumericDelimited\","));

    s = Sanwaf.getDetects(request);
    assertTrue(s == null || s.isEmpty());
  }

  @Test
  public void testTrackIdAndGetErrorsAlphanumericAndMore()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.addParameter("AlphanumericAndMore", "Some Bad! data;----?? ");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);

    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    String s = Sanwaf.getErrors(request);
    assertTrue(s.contains("{\"name\":\"AlphanumericAndMore\""));
  }

  @Test
  public void testTrackIdDisabled()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.addParameter("NumericDelimited", "+foobar");
    boolean trackID = sanwaf.onErrorAddTrackId;
    boolean trackErrors = sanwaf.onErrorAddParmErrors;
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);
    assertNotNull(Sanwaf.getTrackingId(request));
    String s = Sanwaf.getErrors(request);
    assertNotNull(s);

    sanwaf.onErrorAddTrackId = false;
    sanwaf.onErrorAddParmErrors = false;
    request = new MockHttpServletRequest();
    request.addParameter("NumericDelimited", "+foobar");
    result = sanwaf.isThreatDetected(request);
    assertTrue(result);
    assertNull(Sanwaf.getTrackingId(request));
    s = Sanwaf.getErrors(request);
    System.out.println("**********" + s);
    assertNull(s);

    sanwaf.onErrorAddTrackId = trackID;
    sanwaf.onErrorAddParmErrors = trackErrors;
  }

  @Test
  public void testSanwafReload()
  {
    try
    {
      Sanwaf sw = new Sanwaf();
      assertNotNull(sw);
      sw.reLoad();
      assertNotNull(sw);
    }
    catch (IOException ignored)
    {
    }
  }

  @Test
  public void testSanwafInstatiateLoggerOnly()
  {
    try
    {
      Sanwaf sw = new Sanwaf(new com.sanwaf.log.SimpleLogger());
      assertNotNull(sw);
      sw.reLoad();
    }
    catch (IOException ignored)
    {
    }
  }

  @Test
  public void testSanwafInstantiate()
  {
    try
    {
      Sanwaf sw = new Sanwaf();
      assertNotNull(sw);
      sw.reLoad();
    }
    catch (IOException ignored)
    {
    }
  }

  @Test
  public void testSanWafInvalidXML()
  {
    try
    {
      new Sanwaf(new UnitTestLogger(), "invalidXmlFilename.foobar");
      fail("Error, Sanwaf instanciated with invalid xml file");
    }
    catch (IOException ioe)
    {
      assertTrue(ioe instanceof IOException);
    }
  }

  @Test
  public void testSanWafLoggerAndFile()
  {
    try
    {
      Sanwaf sw = new Sanwaf(new UnitTestLogger(), "/sanwaf.xml");
      assertNotNull(sw);
    }
    catch (IOException ioe)
    {
      fail("exception Raised");
    }
  }

  @Test
  public void TestNonMappedParamDefaultToStingWithRegexAlwaysEnabled()
  {
    boolean xssAlways = shield.regexAlways;
    shield.regexAlways = true;
    boolean b = sanwaf.isThreatDetected(null);
    assertFalse(b);

    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.addParameter("foobarTHISisNOTmappedXssError", "<script>alert(1)</script>");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);

    shield.regexAlways = xssAlways;
  }
}

