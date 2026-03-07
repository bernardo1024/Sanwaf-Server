package com.sanwaf.core;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;
import java.util.regex.PatternSyntaxException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class MalformedConfigTest {
  @Test
  public void testMissingGlobalSettings_loadsDisabled() throws IOException {
    Sanwaf sw = new Sanwaf(new UnitTestLogger(), "/sanwaf-no-global-settings.txt");
    assertFalse(sw.config.enabled);
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addParameter("testParam", "abc");
    assertFalse(sw.isThreatDetected(req));
  }

  @Test
  public void testInvalidRegexPattern_throwsOnLoad() {
    assertThrows(PatternSyntaxException.class, () -> new Sanwaf(new UnitTestLogger(), "/sanwaf-invalid-regex.txt"));
  }

  @Test
  public void testNoShields_loadsEmpty() throws IOException {
    Sanwaf sw = new Sanwaf(new UnitTestLogger(), "/sanwaf-no-shields.txt");
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addParameter("anything", "<script>alert(1)</script>");
    assertFalse(sw.isThreatDetected(req));
  }
}
