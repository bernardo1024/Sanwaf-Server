package com.sanwaf.core;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class VerboseTest
{
  private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
  private final PrintStream originalOut = System.out;

  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeEach
  public void setUpStreams()
  {
    System.setOut(new PrintStream(outContent));
  }

  @AfterEach
  public void restoreStreams()
  {
    System.setOut(originalOut);
  }

  @Test
  public void verboseDisabledTest() throws IOException
  {
    sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf.xml");
    String s = outContent.toString();
    assertFalse(s.contains("Settings:"));
    assertFalse(s.contains("RegexAlways=true"));
    assertFalse(s.contains("Shield Secured List: *Ignored*"));
    assertFalse(s.contains("Except for (exclusion list):"));
    assertFalse(s.contains("StringRegexs:"));
    assertFalse(s.contains("customPatterns:"));
    assertFalse(s.contains("Configured/Secured Entries:"));
    assertFalse(s.contains("customPatterns"));
  }

  @Test
  public void verboseEnabledTest() throws IOException
  {
    sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-verbose.xml");
    String s = outContent.toString();
    assertTrue(s.contains("Settings:"));
    assertFalse(s.contains("RegexAlways=true"));
    assertTrue(s.contains("StringRegexs:"));
    assertTrue(s.contains("customPatterns:"));
    assertTrue(s.contains("Secured Items:"));
    assertTrue(s.contains("date="));
    assertTrue(s.contains("Endpoints"));
  }

  @Test
  public void testForceString()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-forceRegex.xml");
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.addParameter("modeParameter", "foobarfoobar");
      assertFalse(sanwaf.isThreatDetected(request));

      request = new MockHttpServletRequest();
      request.addParameter("xxxx", "<script>");
      assertTrue(sanwaf.isThreatDetected(request));
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void verboseEnabledRegexTest() throws IOException
  {
    sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-verboseRegexAlways.xml");
    String s = outContent.toString();
    assertTrue(s.contains("forceStringPatterns=true"));
    assertTrue(s.contains("Shield Secured List: *Ignored*"));
    assertTrue(s.contains("Except for (exclusion list):"));
    assertFalse(s.contains("Configured/Secured Entries:"));
    assertTrue(s.contains("customPatterns"));
    assertTrue(s.contains("date="));
  }

  @Test
  public void verboseChildShieldTest() throws IOException
  {
    sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-childShield.xml");
    String s = outContent.toString();
    assertTrue(s.contains("child-shield=XSS-CHILD"));
  }
}

