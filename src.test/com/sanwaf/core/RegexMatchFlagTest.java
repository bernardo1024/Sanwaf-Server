package com.sanwaf.core;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import com.sanwaf.core.Shield;
import com.sanwaf.core.Sanwaf;

public class RegexMatchFlagTest {
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass() {
    try {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-regex-match-flag.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    } catch (IOException ioe) {
      assertTrue(false);
    }
  }

  @Test
  public void testStringMatchPass() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("stringMatchPass", "javascript:");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testCustomMatchFail() {
    // <item><name>customMatchFail</name><type>r{date-MatchFail}</type></item>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("customMatchFail", "416-555-5555");
    assertTrue(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testCustomMatchPass() {
    // <item><name>customMatchPass</name><type>r{date-MatchPass}</type></item>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("customMatchPass", "416-555-5555");
    assertFalse(sanwaf.isThreatDetected(request));
  }

  @Test
  public void testCustomNoMatch() {
    // <item><name>customNoMatch</name><type>r{date-NoMatch}</type></item>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("customNoMatch", "416-555-5555");
    assertFalse(sanwaf.isThreatDetected(request));
  }
}

