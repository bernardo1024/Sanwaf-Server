package com.sanwaf.core;

import jakarta.servlet.http.Cookie;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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
      fail();
    }
  }

  @Test
  public void testHeader()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("allowlistedHeader", "found");
    req.addHeader("notAllowlistedHeader", "found");

    String value = sanwaf.getAllowListedValue("allowlistedHeader", Sanwaf.AllowListType.HEADER, req);
    assertNotNull(value);
    assertEquals("found", value);

    value = sanwaf.getAllowListedValue("notAllowlistedHeader", Sanwaf.AllowListType.HEADER, req);
    assertNull(value);
  }

  @Test
  public void testCookie()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setCookies(new Cookie("allowlistedCookie", "found"), new Cookie("notAllowlistedCookie", "notFound"));

    String value = sanwaf.getAllowListedValue("allowlistedCookie", Sanwaf.AllowListType.COOKIE, req);
    assertNotNull(value);
    assertEquals("found", value);

    value = sanwaf.getAllowListedValue("notAllowlistedCookie", Sanwaf.AllowListType.COOKIE, req);
    assertNull(value);
  }

  @Test
  public void testNullCookie()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    String value = sanwaf.getAllowListedValue("allowlistedCookie", Sanwaf.AllowListType.COOKIE, req);
    assertNull(value);

    req = new MockHttpServletRequest();
    req.setCookies(new Cookie("notAllowlistedCookie", "notFound"));
    value = sanwaf.getAllowListedValue("allowlistedCookie", Sanwaf.AllowListType.COOKIE, req);
    assertNull(value);
  }

  @Test
  public void testParameter()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addParameter("allowlistedParameter", "found");
    req.addParameter("notAllowlistedParameter", "notFound");

    String value = sanwaf.getAllowListedValue("allowlistedParameter", Sanwaf.AllowListType.PARAMETER, req);
    assertNotNull(value);
    assertEquals("found", value);

    value = sanwaf.getAllowListedValue("notAllowlistedParameter", Sanwaf.AllowListType.PARAMETER, req);
    assertNull(value);
  }

  @Test
  public void testNullType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addHeader("allowlistedHeader", "found");
    req.setCookies(new Cookie("allowlistedCookie", "found"));
    req.addParameter("allowlistedParameter", "found");

    String value = sanwaf.getAllowListedValue("allowlistedParameter", null, req);
    assertNull(value);
    value = sanwaf.getAllowListedValue("allowlistedCookie", null, req);
    assertNull(value);
    value = sanwaf.getAllowListedValue("allowlistedHeader", null, req);
    assertNull(value);
  }

  @Test
  public void testNullRequest()
  {
    String value = sanwaf.getAllowListedValue("allowlistedParameter", Sanwaf.AllowListType.PARAMETER, null);
    assertNull(value);
  }

  @Test
  public void testNullName()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addParameter("allowlistedParameter", "found");
    String value = sanwaf.getAllowListedValue(null, Sanwaf.AllowListType.PARAMETER, req);
    assertNull(value);
  }

}

