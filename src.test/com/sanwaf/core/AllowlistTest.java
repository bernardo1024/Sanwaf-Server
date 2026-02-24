package com.sanwaf.core;

import jakarta.servlet.http.Cookie;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AllowlistTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-Allowlist.xml");
    }
    catch (IOException ioe)
    {
      assertTrue(false);
    }
  }

  @Test
  public void testHeader()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("allowlistedHeader", "found");
    req.addHeader("notAllowlistedHeader", "found");

    String value = sanwaf.getAllowListedValue("allowlistedHeader", Sanwaf.AllowListType.HEADER, req);
    assertEquals(false, value == null);
    assertEquals(true, value.equals("found"));

    value = sanwaf.getAllowListedValue("notAllowlistedHeader", Sanwaf.AllowListType.HEADER, req);
    assertEquals(true, value == null);
  }

  @Test
  public void testCookie()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setCookies(new Cookie("allowlistedCookie", "found"), new Cookie("notAllowlistedCookie", "notFound"));

    String value = sanwaf.getAllowListedValue("allowlistedCookie", Sanwaf.AllowListType.COOKIE, req);
    assertEquals(false, value == null);
    assertEquals(true, value.equals("found"));

    value = sanwaf.getAllowListedValue("notAllowlistedCookie", Sanwaf.AllowListType.COOKIE, req);
    assertEquals(true, value == null);
  }

  @Test
  public void testNullCookie()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    String value = sanwaf.getAllowListedValue("allowlistedCookie", Sanwaf.AllowListType.COOKIE, req);
    assertEquals(true, value == null);

    req = new MockHttpServletRequest();
    req.setCookies(new Cookie("notAllowlistedCookie", "notFound"));
    value = sanwaf.getAllowListedValue("allowlistedCookie", Sanwaf.AllowListType.COOKIE, req);
    assertEquals(true, value == null);
  }

  @Test
  public void testParameter()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addParameter("allowlistedParameter", "found");
    req.addParameter("notAllowlistedParameter", "notFound");

    String value = sanwaf.getAllowListedValue("allowlistedParameter", Sanwaf.AllowListType.PARAMETER, req);
    assertEquals(false, value == null);
    assertEquals(true, value.equals("found"));

    value = sanwaf.getAllowListedValue("notAllowlistedParameter", Sanwaf.AllowListType.PARAMETER, req);
    assertEquals(true, value == null);
  }

  @Test
  public void testNullType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("allowlistedHeader", "found");
    req.setCookies(new Cookie("allowlistedCookie", "found"));
    req.addParameter("allowlistedParameter", "found");

    String value = sanwaf.getAllowListedValue("allowlistedParameter", null, req);
    assertEquals(true, value == null);
    value = sanwaf.getAllowListedValue("allowlistedCookie", null, req);
    assertEquals(true, value == null);
    value = sanwaf.getAllowListedValue("allowlistedHeader", null, req);
    assertEquals(true, value == null);
  }

  @Test
  public void testNullRequest()
  {
    String value = sanwaf.getAllowListedValue("allowlistedParameter", Sanwaf.AllowListType.PARAMETER, null);
    assertEquals(true, value == null);
  }

  @Test
  public void testNullName()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addParameter("allowlistedParameter", "found");
    String value = sanwaf.getAllowListedValue(null, Sanwaf.AllowListType.PARAMETER, req);
    assertEquals(true, value == null);
  }

}

