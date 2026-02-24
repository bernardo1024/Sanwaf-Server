package com.sanwaf.core;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;

import static org.junit.Assert.assertTrue;

public class ModeDetectLoggingTest
{
  private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
  private final PrintStream originalOut = System.out;

  static Sanwaf sanwaf;
  static Shield shield;

  @Before
  public void setUpStreams()
  {
    System.setOut(new PrintStream(outContent));
  }

  @After
  public void restoreStreams()
  {
    System.setOut(originalOut);
  }

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-modes.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    }
    catch (IOException ioe)
    {
      assertTrue(false);
    }
  }

  @Test
  public void testDatatypeDetect1()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("endpointRegex", "abc");
    sanwaf.isThreatDetected(request, true);
    String s = outContent.toString();
    assertTrue(s.contains("\"DETECT\",\"type\":\"INLINE_REGEX\""));
  }

  @Test
  public void testDatatypeDetect()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.addParameter("numericdelimited", "abc");
    sanwaf.isThreatDetected(request, true);
    String s = outContent.toString();
    assertTrue(s.contains("\"delimiter\":\",\""));

    request = new MockHttpServletRequest();
    request.addParameter("alphanumericandmore", "!!@$#$");
    sanwaf.isThreatDetected(request, true);
    s = outContent.toString();
    assertTrue(s.contains("\"morechars\":\"' !\""));

    request = new MockHttpServletRequest();
    request.addParameter("constant", "abc");
    sanwaf.isThreatDetected(request, true);
    s = outContent.toString();
    assertTrue(s.contains("\"constant\":\"y n \""));

    request = new MockHttpServletRequest();
    request.addParameter("regex", "abc");
    sanwaf.isThreatDetected(request, true);
    s = outContent.toString();
    assertTrue(s.contains("\"regex\":\"^\\\\d{4}\\\\-(?:0?[1-9]|1[012])\\\\-(?:0?[1-9]|[12][0-9]|3[01])$\""));

    request = new MockHttpServletRequest();
    request.addParameter("endpointRegex", "abc");
    sanwaf.isThreatDetected(request, true);
    s = outContent.toString();
    assertTrue(s.contains("\"DETECT\",\"type\":\"INLINE_REGEX\""));

    request = new MockHttpServletRequest();
    request.addParameter("max-min-value", "abclkajdflkjasdklfjaskldfjaskldfjlkasjflkasjflkasdjfklasjfklasdjflkasdjfk");
    sanwaf.isThreatDetected(request, true);
    s = outContent.toString();
    assertTrue(s.contains(""));

    request = new MockHttpServletRequest();
    request.addParameter("format", "abc@#$#$#$");
    sanwaf.isThreatDetected(request, true);
    s = outContent.toString();
    assertTrue(s.contains(""));

    request = new MockHttpServletRequest();
    request.addParameter("related-simple-required-parent-child", "<script>abc23@!##");
    sanwaf.isThreatDetected(request, true);
    s = outContent.toString();
    assertTrue(s.contains(""));

    request = new MockHttpServletRequest();
    request.addParameter("dependentparent", "123");
    request.addParameter("dependentformat", "<script>abc23@!##");
    sanwaf.isThreatDetected(request, true, true);
    s = outContent.toString();
    assertTrue(s.contains("\"formats\":{\"key\":\"123\""));
    System.out.println(s);
  }
}

