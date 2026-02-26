package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.MethodOrderer;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@TestMethodOrder(MethodOrderer.MethodName.class)
public class SanwafIsThreatTest
{
  static Sanwaf sanwaf;

  @BeforeAll
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
  public void testSanWafIsThreat()
  {
    boolean b = sanwaf.isThreat("<script>alert(1)</script>");
    assertTrue(b);

    b = sanwaf.isThreat("alert(1)");
    assertFalse(b);
  }

  @Test
  public void testThreatWithNull()
  {
    boolean b = sanwaf.isThreat(null);
    assertFalse(b);
  }

  @Test
  public void testSanWafIsThreatSetAttributesParameters()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("<script>alert(1)</script>", null, request);
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);
    String s = Sanwaf.getErrors(request);
    assertNotNull(s);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("< script>alert(1)</ script>", null, request);
    assertFalse(result);
    trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);
    s = Sanwaf.getErrors(request);
    assertNull(s);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("<script>alert(1)</script>", null, request);
    assertTrue(result);
    trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);
    s = Sanwaf.getErrors(request);
    assertNotNull(s);
  }

  @Test
  public void testSanWafIsThreatDoNotAddErrorParms()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    Sanwaf.SanwafConfig saved = sanwaf.config;
    sanwaf.config = saved.toBuilder().onErrorAddParmErrors(false).build();
    boolean result = sanwaf.isThreat("<script>alert(1)</script>", null, request);
    assertTrue(result);
    String trackId = Sanwaf.getTrackingId(request);
    assertNotNull(trackId);
    String s = Sanwaf.getErrors(request);
    assertNotNull(s);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("valid text", null, request);
    assertFalse(result);
    s = Sanwaf.getErrors(request);
    assertNull(s);

    sanwaf.config = saved;
  }

  @Test
  public void testSanWafIsThreatWithShieldName()
  {
    boolean result = sanwaf.checkValueForShieldThreats("<script>alert(1)</script>", "XSS", null);
    assertTrue(result);

    result = sanwaf.checkValueForShieldThreats("<script>alert(1)</script>", "OTHER", null);
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatNumeric()
  {
    boolean result = Sanwaf.isThreat("abc123", "<item><name>numeric</name><type>n</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);

    result = Sanwaf.isThreat("-123.456", "<item><name>numeric</name><type>n</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatNumericDelimited()
  {
    boolean result = Sanwaf.isThreat("abc123", "<item><name>numericDelimited</name><type>n{,}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);

    result = Sanwaf.isThreat("-123.456,789", "<item><name>numericDelimited</name><type>n{,}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatAlphanumeric()
  {
    boolean result = Sanwaf.isThreat("abc123!!!", "<item><name>alphanumeric</name><type>a</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);

    result = Sanwaf.isThreat("abc123", "<item><name>alphanumeric</name><type>a</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatAlphanumericAndMore()
  {
    boolean result = Sanwaf.isThreat("abc123!!!", "<item><name>alphanumericAndMore</name><type>a{?\\s:}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);

    result = Sanwaf.isThreat("abc  123", "<item><name>alphanumericAndMore</name><type>a{?\\s:}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatChar()
  {
    boolean result = Sanwaf.isThreat("abc123!!!", "<item><name>char</name><type>c</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);

    result = Sanwaf.isThreat("a", "<item><name>char</name><type>c</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatRegex()
  {
    boolean result = Sanwaf.isThreat("abc123!!!", "<item><name>regex</name><type>r{telephone}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result);

    result = Sanwaf.isThreat("555-555-5555", "<item><name>regex</name><type>r{telephone}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatXRegex()
  {
    boolean result = Sanwaf.isThreat("noName",
        "<item><name>regex</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result);

    result = Sanwaf.isThreat("abc123!!!", "<item><name></name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result);

    result = Sanwaf.isThreat("abc123!!!",
        "<item><name>noXmldefined</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result);

    result = Sanwaf.isThreat("abc123!!!", "<item><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result);

    result = Sanwaf.isThreat("123.123.1234",
        "<item><name>regex</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertFalse(result);

    result = Sanwaf.isThreat("123.123.1234", "<item><name></name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertFalse(result);

    result = Sanwaf.isThreat("123.123.1234",
        "<item><name>noXmldefined</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertFalse(result);

    result = Sanwaf.isThreat("123.123.1234", "<item><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatConstant()
  {
    boolean result = Sanwaf.isThreat("abc123!!!", "<item><name>constant</name><type>k{FOO,BAR,FAR}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result);

    result = Sanwaf.isThreat("FOO", "<item><name>constant</name><type>k{FOO,BAR,FAR}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatJava()
  {
    // j{} type is blocked on the static API path (no shield) — falls back to string validation
    boolean result = Sanwaf.isThreat("100", "<item><name>java</name><type>j{com.sanwaf.core.JavaClass.over10TrueElseFalse()}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);

    result = Sanwaf.isThreat("9", "<item><name>java</name><type>j{com.sanwaf.core.JavaClass.over10TrueElseFalse()}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

  @Test
  public void testSanWafIsThreatMaxMinMsgUri()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    boolean result = Sanwaf.isThreat("12345", "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertFalse(result);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    result = Sanwaf.isThreat("1", "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    result = Sanwaf.isThreat("123456", "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result);

    request = new MockHttpServletRequest();
    request.setRequestURI("/badUri");
    result = Sanwaf.isThreat("123456", "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result);
  }

  @Test
  public void testSanWafIsThreatViolateMin()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    boolean result = Sanwaf.isThreat("3", "<item><name>invalidMin</name><type>n</type><max>5</max><min>2</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result);
  }

  @Test
  public void testSanWafIsThreatDynamicXmlInvalidShieldName()
  {
    boolean result = Sanwaf.isThreat("<script>alert(1)</script>", "<item><name>string</name><type>s</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertFalse(result);
  }

}

