package com.sanwaf.core;

import jakarta.servlet.http.Cookie;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

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
      assertTrue(false);
    }
  }

  @Test
  public void testXssTooBig()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    boolean b = shield.threat(req, shield.parameters, "String", breakMaxSizeString, false, false);
    assertEquals(false, b);
  }

  @Test
  public void testNullKeyValue()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    boolean b = shield.threat(req, shield.parameters, null, "<script>alert(1)</script>", false, false);
    assertEquals(false, b);
    b = shield.threat(req, shield.parameters, "String", null, false, false);
    assertEquals(false, b);
  }

  @Test
  public void testUnprotectedParameter()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    boolean b = shield.threat(req, shield.parameters, "foobarNotInParmStore", "<script>alert(1)</script>", false, false);
    assertEquals(false, b);
  }

  @Test
  public void testThreatNoMetadata()
  {
    boolean b = shield.threat("<script>alert(1)</script>", false);
    assertEquals(true, b);
  }

  @Test
  public void testMetadataGetFromIndex()
  {
    String s = shield.parameters.getFromIndex("*foo");
    assertEquals(null, s);

    s = shield.parameters.getFromIndex("foo*");
    assertEquals(null, s);

    s = shield.parameters.getFromIndex("foo[*]");
    assertEquals(null, s);

  }

  @Test
  public void disableSanwafTest()
  {
    sanwaf.enabled = false;
    testNumeric(false);
    sanwaf.enabled = true;
  }

  @Test
  public void sanwafInvalidHttpRequestTest()
  {
    MockHttpServletRequest request = null;
    assertEquals(false, sanwaf.isThreatDetected(request));
    assertEquals(false, sanwaf.isThreatDetected(null));
  }

  @Test
  public void enabledTest()
  {
    shield.parameters.enabled = true;
    shield.headers.enabled = true;
    shield.cookies.enabled = true;
    testNumeric(true);
  }

  @Test
  public void disabledTest()
  {
    shield.parameters.enabled = false;
    shield.headers.enabled = false;
    shield.cookies.enabled = false;
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

