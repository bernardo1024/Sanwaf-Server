package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SanwafIsThreatTest
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
      assertTrue(false);
    }
  }

  @Test
  public void testSanWafIsThreat()
  {
    boolean b = sanwaf.isThreat("<script>alert(1)</script>");
    assertEquals(true, b);

    b = sanwaf.isThreat("alert(1)");
    assertEquals(false, b);
  }

  @Test
  public void testThreatWithNull()
  {
    boolean b = sanwaf.isThreat(null);
    assertTrue(!b);
  }

  @Test
  public void testSanWafIsThreatSetAttributesParameters()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean result = sanwaf.isThreat("<script>alert(1)</script>", null, request);
    assertTrue(result == true);
    String trackId = Sanwaf.getTrackingId(request);
    assertTrue(trackId != null);
    String s = Sanwaf.getErrors(request);
    assertTrue(s != null);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("< script>alert(1)</ script>", null, request);
    assertTrue(result == false);
    trackId = Sanwaf.getTrackingId(request);
    assertTrue(trackId != null);
    s = Sanwaf.getErrors(request);
    assertTrue(s == null);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("<script>alert(1)</script>", null, request);
    assertEquals(true, result);
    trackId = Sanwaf.getTrackingId(request);
    assertTrue(trackId != null);
    s = Sanwaf.getErrors(request);
    assertTrue(s != null);
  }

  @Test
  public void testSanWafIsThreatDoNotAddErrorParms()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    boolean orig = sanwaf.onErrorAddParmErrors;
    sanwaf.onErrorAddParmErrors = false;
    boolean result = sanwaf.isThreat("<script>alert(1)</script>", null, request);
    assertTrue(result == true);
    String trackId = Sanwaf.getTrackingId(request);
    assertTrue(trackId != null);
    String s = Sanwaf.getErrors(request);
    assertTrue(s != null);

    request = new MockHttpServletRequest();
    result = sanwaf.isThreat("valid text", null, request);
    assertTrue(result == false);
    s = Sanwaf.getErrors(request);
    assertTrue(s == null);

    sanwaf.onErrorAddParmErrors = orig;
  }

  @Test
  public void testSanWafIsThreatWithShieldName()
  {
    boolean result = sanwaf.checkValueForShieldThreats("<script>alert(1)</script>", "XSS", null);
    assertTrue(result == true);

    result = sanwaf.checkValueForShieldThreats("<script>alert(1)</script>", "OTHER", null);
    assertTrue(result == false);
  }

  @Test
  public void testSanWafIsThreatNumeric()
  {
    boolean result = Sanwaf.isThreat("abc123", "<item><name>numeric</name><type>n</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("-123.456", "<item><name>numeric</name><type>n</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == false);
  }

  @Test
  public void testSanWafIsThreatNumericDelimited()
  {
    boolean result = Sanwaf.isThreat("abc123", "<item><name>numericDelimited</name><type>n{,}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("-123.456,789", "<item><name>numericDelimited</name><type>n{,}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == false);
  }

  @Test
  public void testSanWafIsThreatAlphanumeric()
  {
    boolean result = Sanwaf.isThreat("abc123!!!", "<item><name>alphanumeric</name><type>a</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("abc123", "<item><name>alphanumeric</name><type>a</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == false);
  }

  @Test
  public void testSanWafIsThreatAlphanumericAndMore()
  {
    boolean result = Sanwaf.isThreat("abc123!!!", "<item><name>alphanumericAndMore</name><type>a{?\\s:}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("abc  123", "<item><name>alphanumericAndMore</name><type>a{?\\s:}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == false);
  }

  @Test
  public void testSanWafIsThreatChar()
  {
    boolean result = Sanwaf.isThreat("abc123!!!", "<item><name>char</name><type>c</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("a", "<item><name>char</name><type>c</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == false);
  }

  @Test
  public void testSanWafIsThreatRegex()
  {
    boolean result = Sanwaf.isThreat("abc123!!!", "<item><name>regex</name><type>r{telephone}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("555-555-5555", "<item><name>regex</name><type>r{telephone}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result == false);
  }

  @Test
  public void testSanWafIsThreatXRegex()
  {
    boolean result = Sanwaf.isThreat("noName",
        "<item><name>regex</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("abc123!!!", "<item><name></name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("abc123!!!",
        "<item><name>noXmldefined</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("abc123!!!", "<item><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("123.123.1234",
        "<item><name>regex</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result == false);

    result = Sanwaf.isThreat("123.123.1234", "<item><name></name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result == false);

    result = Sanwaf.isThreat("123.123.1234",
        "<item><name>noXmldefined</name><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result == false);

    result = Sanwaf.isThreat("123.123.1234", "<item><type>x{(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{3})(?:[ .-]{1})(?:[0-9]{4})}</type><max>12</max><min>12</min><msg></msg><uri></uri></item>");
    assertTrue(result == false);
  }

  @Test
  public void testSanWafIsThreatConstant()
  {
    boolean result = Sanwaf.isThreat("abc123!!!", "<item><name>constant</name><type>k{FOO,BAR,FAR}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("FOO", "<item><name>constant</name><type>k{FOO,BAR,FAR}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == false);
  }

  @Test
  public void testSanWafIsThreatJava()
  {
    boolean result = Sanwaf.isThreat("100", "<item><name>java</name><type>j{com.sanwaf.core.JavaClass.over10TrueElseFalse()}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == true);

    result = Sanwaf.isThreat("9", "<item><name>java</name><type>j{com.sanwaf.core.JavaClass.over10TrueElseFalse()}</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == false);
  }

  @Test
  public void testSanWafIsThreatMaxMinMsgUri()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    boolean result = Sanwaf.isThreat("12345", "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result == false);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    result = Sanwaf.isThreat("1", "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result == true);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    result = Sanwaf.isThreat("123456", "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result == true);

    request = new MockHttpServletRequest();
    request.setRequestURI("/badUri");
    result = Sanwaf.isThreat("123456", "<item><name>MaxMinMsgUri</name><type>n</type><max>5</max><min>5</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result == true);
  }

  @Test
  public void testSanWafIsThreatViolateMin()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foobar");
    boolean result = Sanwaf.isThreat("3", "<item><name>invalidMin</name><type>n</type><max>5</max><min>2</min><msg>max(5)min(5)uri(</msg><uri>/foobar</uri></item>");
    assertTrue(result == true);
  }

  @Test
  public void testSanWafIsThreatDynamicXmlInvalidShieldName()
  {
    boolean result = Sanwaf.isThreat("<script>alert(1)</script>", "<item><name>string</name><type>s</type><max></max><min></min><msg></msg><uri></uri></item>");
    assertTrue(result == false);
  }

}

