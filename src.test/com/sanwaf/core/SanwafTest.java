package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.MethodOrderer;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@TestMethodOrder(MethodOrderer.MethodName.class)
public class SanwafTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeAll
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
    boolean result = sanwaf.isThreatDetected(request);
    assertFalse(result);
  }

  @Test
  public void testXssWithThreat()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("String", "<script>alert(1);</script>");
    boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);
  }

  @Test
  public void testTrackIdAndGetErrorsNumbersDelimited()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("NumericDelimited", "+foobar");
    boolean result = sanwaf.isThreatDetected(request);
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
    request.addParameter("AlphanumericAndMore", "Some Bad! data;----?? ");
    boolean result = sanwaf.isThreatDetected(request);
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
    request.addParameter("NumericDelimited", "+foobar");
    boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);
    assertNotNull(Sanwaf.getTrackingId(request));
    String s = Sanwaf.getErrors(request);
    assertNotNull(s);

    Sanwaf.SanwafConfig saved = sanwaf.config;
    sanwaf.config = saved.toBuilder().onErrorAddTrackId(false).onErrorAddParmErrors(false).build();
    request = new MockHttpServletRequest();
    request.addParameter("NumericDelimited", "+foobar");
    result = sanwaf.isThreatDetected(request);
    assertTrue(result);
    assertNull(Sanwaf.getTrackingId(request));
    s = Sanwaf.getErrors(request);
    System.out.println("**********" + s);
    assertNull(s);

    sanwaf.config = saved;
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
  public void testSanwafInstantiateLoggerOnly()
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
    assertThrows(IOException.class, () -> new Sanwaf(new UnitTestLogger(), "invalidXmlFilename.foobar"));
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
    UnitTestUtil.setField(shield, "regexAlways", true);
    boolean b = sanwaf.isThreatDetected(null);
    assertFalse(b);

    MockHttpServletRequest request = new MockHttpServletRequest();
    //noinspection SpellCheckingInspection
    request.addParameter("foobarTHISisNOTmappedXssError", "<script>alert(1)</script>");
    boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);

    UnitTestUtil.setField(shield, "regexAlways", xssAlways);
  }

  @Test
  public void testIsThreatDetectedWithShieldList()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("String", "<script>alert(1)</script>");
    assertTrue(sanwaf.isThreatDetected(request, Collections.singletonList("XSS"), false));

    request = new MockHttpServletRequest();
    request.addParameter("String", "<script>alert(1)</script>");
    assertFalse(sanwaf.isThreatDetected(request, Collections.singletonList("ParmLength"), false));

    request = new MockHttpServletRequest();
    request.addParameter("String", "<script>alert(1)</script>");
    assertTrue(sanwaf.isThreatDetected(request, null, false));
  }
}

