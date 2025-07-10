package com.sanwaf.core;

import static org.junit.Assert.*;

import java.io.IOException;

import jakarta.servlet.http.Cookie;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import com.sanwaf.core.Shield;
import com.sanwaf.core.Sanwaf;

public class ModeTest {
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass() {
    try {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-modes.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    } catch (IOException ioe) {
      assertTrue(false);
    }
  }

  @Test
  public void testColonedParameters() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("p1", "foo<body onload='alert(1)'>bar");
    assertTrue(sanwaf.isThreatDetected(request, true, false));
    assertTrue(Sanwaf.getDetects(request) != null);
  }

  @Test
  public void testParameter() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("modeParameter", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testParameterString() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("modeParameterString", "javascript: ");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("modeParameterString", "javascript: <script> ");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testParameterRegex() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("modeParameterRegex", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testParameterBlock() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameter-BLOCK", "foobarfoobar");
    assertTrue(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testParameterDisabled() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameter-DISABLED", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testParameterNoMode() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameter-NO-MODE", "foobarfoobar");
    assertTrue(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testParameterItemRuleCombinations() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameter-DETECT-BLOCK", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameterString-DETECT-DISABLED", "javascript: <script> ");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameterRegex-BLOCK-BLOCK", "foobarfoobar");
    assertTrue(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameterRegex-BLOCK-DISABLED", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testHeader() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("modeHeader", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testHeaderNoMode() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("modeHeader-NO-MODE", "<script>");
    assertTrue(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testHeaderNoModeLargeValue() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("modeParameter-DETECT2", ":RULE-IS-DETECT<script> 12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testCookie() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setCookies(new Cookie("modeCookie", "foobarfoobar"));
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testCookieNoMode() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setCookies(new Cookie("modeCookie-NO-MODE", "foobarfoobar"));
    assertTrue(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testEndPointDetect() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameter-DETECT", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));
    String s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.contains("modeeParameter-DETECT"));

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameterString-DETECT", "javascript: <script> ");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameterRegex-DETECT", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameter-DETECT", "foobarfoobar");
    request.addParameter("modeeParameterString", "javascript: <script> ");
    request.addParameter("modeeParameterRegex-DETECT", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testEndPointBlock() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameter-BLOCK", "foobarfoobar");
    assertTrue(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testEndPointDisabled() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameter-DISABLED", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testEndPointNoMode() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameter-NO-MODE", "foobarfoobar");
    assertTrue(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testEndPointItemRuleCombinations() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameter-DETECT-BLOCK", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameterString-DETECT-DISABLED", "javascript: <script> ");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameterRegex-BLOCK-BLOCK", "foobarfoobar");
    assertTrue(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("modeeParameterRegex-BLOCK-DISABLED", "foobarfoobar");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testDatatypeDetect() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("char", "cc");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("numeric", "abc");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("numericdelimited", "abc");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("alphanumeric", "!@#$");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("alphanumericandmore", "!!@$#$");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("constant", "abc");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("regex", "abc");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("endpointRegex", "abc");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("max-min-value", "abclkajdflkjasdklfjaskldfjaskldfjlkasjflkasjflkasdjfklasjfklasdjflkasdjfk");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("format", "abc");
    assertFalse(sanwaf.isThreatDetected(request));

    request = new MockHttpServletRequest();
    request.addParameter("dependentparent", "123");
    request.addParameter("dependentformat", "<script>abc23@!##");
    assertFalse(sanwaf.isThreatDetected(request));
    String s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.length() > 0);

  }

  @Test
  public void testTest() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("numericdelimited", "abc");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testRegexModeDetextNoModeOnParmDetect() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("regexParmNoModeWithRegexDetectMode", "abcd");
    assertFalse(sanwaf.isThreatDetected(request));
  }

}

