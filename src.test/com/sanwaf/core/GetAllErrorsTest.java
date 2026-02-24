package com.sanwaf.core;

import jakarta.servlet.http.Cookie;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertTrue;

public class GetAllErrorsTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-getAllErrors.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    }
    catch (IOException ioe)
    {
      assertTrue(false);
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
    assertTrue(getItemCount(b, "\"item\":{\"name\":\"") == 2);
    String s = sanwaf.getAllErrors(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_BLOCK\""));
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_NO_MODE\""));
    assertTrue(getItemCount(s, "\"item\":{\"name\":\"") == 2);
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
    assertTrue(getItemCount(b, "\"item\":{\"name\":\"") == 1);
    String s = sanwaf.getAllErrors(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_BLOCK\""));
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_NO_MODE\""));
    assertTrue(getItemCount(s, "\"item\":{\"name\":\"") == 2);
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
    assertTrue(getItemCount(b, "\"item\":{\"name\":\"") == 1);
    String s = sanwaf.getAllErrors(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_BLOCK\""));
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_NO_MODE\""));
    assertTrue(getItemCount(s, "\"item\":{\"name\":\"") == 2);
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
    assertTrue(getItemCount(b, "\"item\":{\"name\":\"") == 1);
    String s = sanwaf.getAllErrors(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_BLOCK\""));
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_NO_MODE\""));
    assertTrue(getItemCount(s, "\"item\":{\"name\":\"") == 2);
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
    assertTrue(getItemCount(s, "\"item\":{\"name\":\"") == 2);
    s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_DETECT\""));
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"string_DETECT_ALL\""));
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
    assertTrue(getItemCount(s, "\"item\":{\"name\":\"") == 2);
    assertTrue(s != null && s.contains(""));
    s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.contains(""));
  }

  static int getItemCount(String s, String match)
  {
    int count = 0;
    int start = 0;
    int end = 0;
    while (true)
    {
      start = s.indexOf(match, end);
      if (start < 0)
      {
        break;
      }
      end = start + match.length();
      count++;
    }
    return count;
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
    assertTrue(getItemCount(b, "\"item\":{\"name\":\"") == 1);
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
    assertTrue(getItemCount(b, "\"item\":{\"name\":\"") == 1);
    String s = sanwaf.getAllErrors(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_BLOCK\""));
    assertTrue(getItemCount(s, "\"item\":{\"name\":\"") == 1);
  }

  @Test
  public void testEndpointDetect()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/detect.jsp");
    request.addParameter("estring_DETECT", "sDETECT");
    assertTrue(!sanwaf.isThreatDetected(request, true, true));
    String s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_DETECT\""));
    assertTrue(getItemCount(s, "\"item\":{\"name\":\"") == 1);
  }

  @Test
  public void testEndpointDetectAll()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/detectall.jsp");
    request.addParameter("estring_DETECT_ALL", "sDETECTALL");
    assertTrue(!sanwaf.isThreatDetected(request, true, true));
    String s = Sanwaf.getDetects(request);
    assertTrue(s != null && s.contains("\"item\":{\"name\":\"estring_DETECT_ALL\""));
    assertTrue(getItemCount(s, "\"item\":{\"name\":\"") == 1);
  }

}

