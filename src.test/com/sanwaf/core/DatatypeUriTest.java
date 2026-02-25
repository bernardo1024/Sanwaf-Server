package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class DatatypeUriTest
{
  static Sanwaf sanwaf;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-uri.xml");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testNumeric()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar");
    req.addParameter("Numeric", "123");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/invalid");
    req.addParameter("Numeric", "123");
    assertTrue(sanwaf.isThreatDetected(req));
  }

  @Test
  public void testNumericDelimitedType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar");
    req.addParameter("NumericDelimited", "123,456");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/invalid");
    req.addParameter("NumericDelimited", "123,456");
    assertTrue(sanwaf.isThreatDetected(req));
  }

  @Test
  public void testAlphanumeric()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar");
    req.addParameter("Alphanumeric", "abc123");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/invalid");
    req.addParameter("Alphanumeric", "abc123");
    assertTrue(sanwaf.isThreatDetected(req));
  }

  @Test
  public void testAlphanumericAndMoreType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar");
    req.addParameter("AlphanumericAndMore", "abc123 :");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/invalid");
    req.addParameter("AlphanumericAndMore", "abc123 :");
    assertTrue(sanwaf.isThreatDetected(req));
  }

  @Test
  public void testChar()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar");
    req.addParameter("Char", "c");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/invalid");
    req.addParameter("Char", "c");
    assertTrue(sanwaf.isThreatDetected(req));
  }

  @Test
  public void testRegexType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar");
    req.addParameter("Regex", "555-555-5555");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/invalid");
    req.addParameter("Regex", "555-555-5555");
    assertTrue(sanwaf.isThreatDetected(req));
  }

  @Test
  public void testConstantType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar");
    req.addParameter("Constant", "FOO");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/invalid");
    req.addParameter("Constant", "FOO");
    assertTrue(sanwaf.isThreatDetected(req));
  }

  @Test
  public void testJava()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar");
    req.addParameter("Java", "10");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/invalid");
    req.addParameter("Java", "10");
    assertTrue(sanwaf.isThreatDetected(req));
  }

  @Test
  public void testString()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar");
    req.addParameter("String", "valid string");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/invalid");
    req.addParameter("String", "valid string");
    assertTrue(sanwaf.isThreatDetected(req));
  }

  @Test
  public void testOpen()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar");
    req.addParameter("Open", "valid string");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/invalid");
    req.addParameter("Open", "valid string");
    assertTrue(sanwaf.isThreatDetected(req));
  }

  @Test
  public void testMultipleUris()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar");
    req.addParameter("MultipleUris", "123456");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/far/nar");
    req.addParameter("MultipleUris", "123456");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/tar/mar");
    req.addParameter("MultipleUris", "123456");
    assertFalse(sanwaf.isThreatDetected(req));

    req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/invalid");
    req.addParameter("MultipleUris", "123456");
    assertTrue(sanwaf.isThreatDetected(req));
  }
}

