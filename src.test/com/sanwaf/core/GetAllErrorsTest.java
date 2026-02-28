package com.sanwaf.core;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class GetAllErrorsTest
{
  static Sanwaf sanwaf;

  @BeforeAll
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-getAllErrors.xml.broken");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testParameter()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("string_BLOCK", "sBLOCK");
    request.addParameter("string_NO_MODE", "sBLOCK");
    assertTrue(sanwaf.isThreatDetected(request, true, false));
    String b = Sanwaf.getErrors(request);
    assertTrue(b != null && b.contains("\"item\":{\"name\":\""));
    assertEquals(2, getItemCount(b, "\"item\":{\"name\":\""));
    String s = sanwaf.getAllErrors(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_BLOCK\""));
    assertTrue(s.contains("\"item\":{\"name\":\"string_NO_MODE\""));
    assertEquals(2, getItemCount(s, "\"item\":{\"name\":\""));
  }

  @Test
  public void testHeader()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("string_BLOCK", "sBLOCK");
    request.addHeader("string_NO_MODE", "sBLOCK");
    assertTrue(sanwaf.isThreatDetected(request));
    String b = Sanwaf.getErrors(request);
    assertTrue(b != null && b.contains("\"item\":{\"name\":\""));
    assertEquals(1, getItemCount(b, "\"item\":{\"name\":\""));
    String s = sanwaf.getAllErrors(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_BLOCK\""));
    assertTrue(s.contains("\"item\":{\"name\":\"string_NO_MODE\""));
    assertEquals(2, getItemCount(s, "\"item\":{\"name\":\""));
  }

  @Test
  public void testCookie()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    Cookie[] cookies = new Cookie[] { new Cookie("string_BLOCK", "sBLOCK"), new Cookie("string_NO_MODE", "sBLOCK") };
    request.setCookies(cookies);
    request.setCookies(cookies);
    assertTrue(sanwaf.isThreatDetected(request));
    String b = Sanwaf.getErrors(request);
    assertTrue(b != null && b.contains("\"item\":{\"name\":\""));
    assertEquals(1, getItemCount(b, "\"item\":{\"name\":\""));
    String s = sanwaf.getAllErrors(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_BLOCK\""));
    assertTrue(s.contains("\"item\":{\"name\":\"string_NO_MODE\""));
    assertEquals(2, getItemCount(s, "\"item\":{\"name\":\""));
  }

  @Test
  public void testEndpoint()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/block.jsp");
    request.addParameter("estring_BLOCK", "sBLOCK");
    request.addParameter("estring_NO_MODE", "sBLOCK");
    assertTrue(sanwaf.isThreatDetected(request));
    String b = Sanwaf.getErrors(request);
    assertTrue(b != null && b.contains("\"item\":{\"name\":\""));
    assertEquals(1, getItemCount(b, "\"item\":{\"name\":\""));
    String s = sanwaf.getAllErrors(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_BLOCK\""));
    assertTrue(s.contains("\"item\":{\"name\":\"estring_NO_MODE\""));
    assertEquals(2, getItemCount(s, "\"item\":{\"name\":\""));
  }

  @Test
  public void testParameters()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("string_DETECT", "sDETECT");
    request.addParameter("string_DETECT_ALL", "sDETECTALL");
    request.addParameter("string_BLOCK", "sBLOCK");
    request.addParameter("string_DISABLED", "sBLOCK");
    request.addParameter("string_NO_MODE", "sBLOCK");
    assertTrue(sanwaf.isThreatDetected(request));
    String s = sanwaf.getAllErrors(request);
    assertTrue(s != null && s.contains("\"action\":\"BLOCK\",\"type\":\"STRING\",\"value\":\"sBLOCK\""));
    assertEquals(2, getItemCount(s, "\"item\":{\"name\":\""));
    s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_DETECT\""));
    assertTrue(s.contains("\"item\":{\"name\":\"string_DETECT_ALL\""));
  }

  @Test
  public void tesCustomParameter()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("custom_DETECT", "--------");
    request.addParameter("custom_DETECT_ALL", "--------");
    request.addParameter("custom_BLOCK", "--------");
    request.addParameter("custom_DISABLED", "--------");
    request.addParameter("custom_NO_MODE", "--------");
    assertTrue(sanwaf.isThreatDetected(request, true));
    String s = sanwaf.getAllErrors(request);
    assertEquals(2, getItemCount(s, "\"item\":{\"name\":\""));
    s = Sanwaf.getDetects(request);
    assertNotNull(s);
  }

  static int getItemCount(String s, String match)
  {
    int count = 0;
    for (int i = s.indexOf(match); i >= 0; i = s.indexOf(match, i + match.length()))
    {
      count++;
    }
    return count;
  }

  @Test
  public void testAllDetectsBeforeBlocksMultiValuedParam()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    // multi_test is defined twice in XML (detect then block), but with combined
    // metadata the block item overwrites the detect item (same key).
    // Single-pass: blocks on first bad value.
    //noinspection SpellCheckingInspection
    request.addParameter("multi_test", "sBLOCKval1", "sBLOCKval2");
    assertTrue(sanwaf.isThreatDetected(request));
    String errors = Sanwaf.getErrors(request);
    assertNotNull(errors);
    assertTrue(errors.contains("\"value\":\"sBLOCKval1\""));
    assertEquals(1, getItemCount(errors, "\"item\":{\"name\":\"multi_test\""));
  }

  @Test
  public void testEndpointNoMode()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/nomode.jsp");
    request.addParameter("estring_NO_MODE", "sBLOCK");
    assertTrue(sanwaf.isThreatDetected(request));
    String b = Sanwaf.getErrors(request);
    assertTrue(b != null && b.contains("\"item\":{\"name\":\"estring_NO_MODE"));
    assertEquals(1, getItemCount(b, "\"item\":{\"name\":\""));
  }

  @Test
  public void testEndpointBlock()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/block.jsp");
    request.addParameter("estring_BLOCK", "sBLOCK");
    assertTrue(sanwaf.isThreatDetected(request));
    String b = Sanwaf.getErrors(request);
    assertTrue(b != null && b.contains("\"item\":{\"name\":\"estring_BLOCK"));
    assertEquals(1, getItemCount(b, "\"item\":{\"name\":\""));
    String s = sanwaf.getAllErrors(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_BLOCK\""));
    assertEquals(1, getItemCount(s, "\"item\":{\"name\":\""));
  }

  @Test
  public void testEndpointDetect()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/detect.jsp");
    request.addParameter("estring_DETECT", "sDETECT");
    assertFalse(sanwaf.isThreatDetected(request, true, true));
    String s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_DETECT\""));
    assertEquals(1, getItemCount(s, "\"item\":{\"name\":\""));
  }

  @Test
  public void testEndpointDetectAll()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/detectall.jsp");
    request.addParameter("estring_DETECT_ALL", "sDETECTALL");
    assertFalse(sanwaf.isThreatDetected(request, true, true));
    String s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_DETECT_ALL\""));
    assertEquals(1, getItemCount(s, "\"item\":{\"name\":\""));
  }

}

