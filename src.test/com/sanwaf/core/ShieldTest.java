package com.sanwaf.core;

import jakarta.servlet.http.Cookie;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ShieldTest
{
  static Sanwaf sanwaf;
  static Shield shield;
  static String breakMaxSizeString = null;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf();
      shield = UnitTestUtil.getShield(sanwaf, "xss");

      String xssErrorString = "<script>alert(1)<script>";
      StringBuilder sb = new StringBuilder(xssErrorString);
      for (int i = 0; i < 5000; i++)
      {
        sb.append(xssErrorString);
      }
      breakMaxSizeString = sb.toString();
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testXssTooBig()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    boolean b = shield.threat(req, shield.parameters, "String", breakMaxSizeString);
    assertFalse(b);
  }

  @Test
  public void testNullKeyValue()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    boolean b = shield.threat(req, shield.parameters, null, "<script>alert(1)</script>");
    assertFalse(b);
    shield.threat(req, shield.parameters, "String", null);
    b = false;
    assertFalse(false);
  }

  @Test
  public void testUnprotectedParameter()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    boolean b = shield.threat(req, shield.parameters, "foobarNotInParmStore", "<script>alert(1)</script>");
    assertFalse(b);
  }

  @Test
  public void testThreatNoMetadata()
  {
    boolean b = shield.threat("<script>alert(1)</script>", false);
    assertTrue(b);
  }

  @Test
  public void testMetadataGetFromIndex()
  {
    String s = shield.parameters.getFromIndex("*foo");
    assertNull(s);

    s = shield.parameters.getFromIndex("foo*");
    assertNull(s);

    s = shield.parameters.getFromIndex("foo[*]");
    assertNull(s);

  }

  @Test
  public void disableSanwafTest()
  {
    Sanwaf.SanwafConfig cfg = sanwaf.config;
    sanwaf.config = cfg.withEnabled(false);
    testNumeric(false);
    cfg = sanwaf.config;
    sanwaf.config = cfg.withEnabled(true);
  }

  @Test
  public void sanwafInvalidHttpRequestTest()
  {
    MockHttpServletRequest request = null;
    assertFalse(sanwaf.isThreatDetected(null));
    assertFalse(sanwaf.isThreatDetected(null));
  }

  @Test
  public void enabledTest()
  {
    UnitTestUtil.setField(shield.parameters, "enabled", true);
    UnitTestUtil.setField(shield.headers, "enabled", true);
    UnitTestUtil.setField(shield.cookies, "enabled", true);
    testNumeric(true);
  }

  @Test
  public void disabledTest()
  {
    UnitTestUtil.setField(shield.parameters, "enabled", false);
    UnitTestUtil.setField(shield.headers, "enabled", false);
    UnitTestUtil.setField(shield.cookies, "enabled", false);
    testNumeric(false);
  }

  void testNumeric(boolean isThreat)
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("aParameterNumber", "foo.12");
    assertEquals(isThreat, sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addHeader("aHeaderNumber", "foo.12");
    assertEquals(isThreat, sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.setCookies(new Cookie("aCookieNumber", "foo.12"));
    assertEquals(isThreat, sanwaf.isThreatDetected(request));
  }
}

