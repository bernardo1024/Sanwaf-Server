package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SanwafIsThreatDynamicTest
{
  static Sanwaf sanwaf;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-isThreat.xml");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testSanWafIsThreatString()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("<script>alert(1)</script>", "XSS", request, "<item><name>string</name><type>s</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("valid string", "XSS", request, "<item><name>string</name><type>s</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("<script>alert(1)</script>", "XSS", request, "<item><name>string</name><type>s</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);
  }

  @Test
  public void testSanWafIsThreatNumeric()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("abc123", "XSS", request, "<item><name>numeric</name><type>n</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("-123.456", "XSS", request, "<item><name>numeric</name><type>n</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatNumericDelimited()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("abc123", "XSS", request, "<item><name>numericDelimited</name><type>n{,}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("-123.456,789", "XSS", request, "<item><name>numericDelimited</name><type>n{,}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatAlphanumeric()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("abc123!!!", "XSS", request, "<item><name>alphanumeric</name><type>a</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("abc123", "XSS", request, "<item><name>alphanumeric</name><type>a</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatAlphanumericAndMore()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("abc123!!!", "XSS", request, "<item><name>alphanumericAndMore</name><type>a{?\\s:}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("abc  123", "XSS", request, "<item><name>alphanumericAndMore</name><type>a{?\\s:}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatChar()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("abc123!!!", "XSS", request, "<item><name>char</name><type>c</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("a", "XSS", request, "<item><name>char</name><type>c</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatRegex()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("abc123!!!", "XSS", request, "<item><name>regex</name><type>r{telephone}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("555-555-5555", "XSS", request, "<item><name>regex</name><type>r{telephone}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatXRegex()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("noName", "XSS", request,
        "<item><name>regex</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    result = sanwaf.isThreat("abc123!!!", "XSS", request,
        "<item><name></name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result);
    trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    result = sanwaf.isThreat("abc123!!!", "XSS", request,
        "<item><name>noXmldefined</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result);
    trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    result = sanwaf.isThreat("abc123!!!", "XSS", request, "<item><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result);
    trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("123.123.1234", "XSS", request,
        "<item><name>regex</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertFalse(result);

    result = sanwaf.isThreat("123.123.1234", "XSS", request,
        "<item><name></name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertFalse(result);

    result = sanwaf.isThreat("123.123.1234", "XSS", request,
        "<item><name>noXmldefined</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertFalse(result);

    result = sanwaf.isThreat("123.123.1234", "XSS", request,
        "<item><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatConstant()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("abc123!!!", "XSS", request, "<item><name>constant</name><type>k{FOO,BAR,FAR}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("FOO", "XSS", request, "<item><name>constant</name><type>k{FOO,BAR,FAR}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatJava()
  {
    // j{} type is blocked on XML-accepting API paths — falls back to string validation
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("100", "XSS", request,
        "<item><name>java</name><type>j{com.sanwaf.core.JavaClass.over10TrueElseFalse()}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("9", "XSS", request,
        "<item><name>java</name><type>j{com.sanwaf.core.JavaClass.over10TrueElseFalse()}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatMaxMinMsgUri()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    boolean result = sanwaf.isThreat("12345", "XSS", request, "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertFalse(result);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    result = sanwaf.isThreat("1", "XSS", request, "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    result = sanwaf.isThreat("123456", "XSS", request, "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result);
    trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);

    request = new MockHttpServletRequest();
    request.setRequestURI("/badUri");
    result = sanwaf.isThreat("123456", "XSS", request, "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result);
    trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);
  }

  @Test
  public void testSanWafIsThreatViolateMin()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    boolean result = sanwaf.isThreat("3", "XSS", request, "<item><name>invalidMin</name><type>n</type><max>5</max><min>2</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);
  }

  @Test
  public void testSanWafIsThreatDynamicXmlInvalidShieldName()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("<script>alert(1)</script>", "INVALID", request, "<item><name>string</name><type>s</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testCacheEvictionBeyondMaxSize()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    for (int i = 0; i < 100; i++)
    {
      String xml = "<item><name>n" + i + "</name><type>n</type><max></max><min></min><msg></msg><uri></uri></item>";
      boolean result = sanwaf.isThreat("12345", "XSS", request, xml);
      assertFalse(result);
    }
  }
}

