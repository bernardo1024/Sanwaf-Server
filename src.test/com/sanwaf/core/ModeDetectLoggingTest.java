package com.sanwaf.core;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ModeDetectLoggingTest {
  private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
  private final PrintStream originalOut = System.out;

  static Sanwaf sanwaf;

  @BeforeEach
  public void setUpStreams() {
    System.setOut(new PrintStream(outContent));
  }

  @AfterEach
  public void restoreStreams() {
    System.setOut(originalOut);
  }

  @BeforeAll
  public static void setUpClass() {
    try {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-modes.xml");
    } catch (IOException ioe) {
      fail();
    }
  }

  @Test
  public void testDatatypeDetect1() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("endpointRegex", "abc");
    sanwaf.isThreatDetected(request, false, true);
    String s = outContent.toString();
    assertTrue(s.contains("\"DETECT\",\"type\":\"INLINE_REGEX\""));
  }

  @Test
  public void testDatatypeDetect() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("numericdelimited", "abc");
    sanwaf.isThreatDetected(request, false, true);
    String s = outContent.toString();
    assertTrue(s.contains("\"delimiter\":\",\""));

    request = new MockHttpServletRequest();
    request.addParameter("alphanumericandmore", "!!@$#$");
    sanwaf.isThreatDetected(request, false, true);
    s = outContent.toString();
    assertTrue(s.contains("\"morechars\":\"' !\""));

    request = new MockHttpServletRequest();
    request.addParameter("constant", "abc");
    sanwaf.isThreatDetected(request, false, true);
    s = outContent.toString();
    assertTrue(s.contains("\"constant\":\"y n \""));

    request = new MockHttpServletRequest();
    request.addParameter("regex", "abc");
    sanwaf.isThreatDetected(request, false, true);
    s = outContent.toString();
    assertTrue(s.contains("\"regex\":\"^\\\\d{4}\\\\-(?:0?[1-9]|1[012])\\\\-(?:0?[1-9]|[12][0-9]|3[01])$\""));

    request = new MockHttpServletRequest();
    request.addParameter("endpointRegex", "abc");
    sanwaf.isThreatDetected(request, false, true);
    s = outContent.toString();
    assertTrue(s.contains("\"DETECT\",\"type\":\"INLINE_REGEX\""));

    request = new MockHttpServletRequest();
    request.addParameter("max-min-value", "abclkajdflkjasdklfjaskldfjaskldfjlkasjflkasjflkasdjfklasjfklasdjflkasdjfk");
    sanwaf.isThreatDetected(request, false, true);
    s = outContent.toString();
    assertTrue(s.contains("\"type\":\"NUMERIC\""));

    request = new MockHttpServletRequest();
    request.addParameter("format", "abc@#$#$#$");
    sanwaf.isThreatDetected(request, false, true);
    s = outContent.toString();
    assertTrue(s.contains("\"format\":\"(###) ###-#### aaa AAA\""));

    // undefined param with forceStringPatterns=false; just verify no exception
    request = new MockHttpServletRequest();
    request.addParameter("related-simple-required-parent-child", "<script>abc23@!##");
    sanwaf.isThreatDetected(request, false, true);

    request = new MockHttpServletRequest();
    request.addParameter("dependentparent", "123");
    request.addParameter("dependentformat", "<script>abc23@!##");
    sanwaf.isThreatDetected(request, true, true);
    s = outContent.toString();
    assertTrue(s.contains("\"formats\":{\"key\":\"123\""));
  }
}
