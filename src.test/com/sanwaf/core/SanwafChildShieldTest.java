package com.sanwaf.core;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.springframework.mock.web.MockHttpServletRequest;

import com.sanwaf.core.Shield;
import com.sanwaf.core.Sanwaf;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SanwafChildShieldTest {
  static Sanwaf sanwaf;

  @BeforeClass
  public static void setUpClass() {
    try {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-childShield.xml");
    } catch (IOException ioe) {
      assertTrue(false);
    }
  }

  @Test
  public void testHasChildShield() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    Shield shield = UnitTestUtil.getShield(sanwaf, "xss");
    assertTrue(shield.childShield.name.equals("XSS-CHILD"));
  }

  @Test
  public void testChildShieldNoMaxViolationThreat() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("String", "javascript: should pass short string has no javascript: test");
    Boolean result = sanwaf.isThreatDetected(request);
    assertFalse(result);
  }

  @Test
  public void testChildShieldMaxViolationThreat() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("String", "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890 javascript: should fail");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);
  }

  @Test
  public void testIsThreatNoMaxViolation() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    String value = "javascript: should pass short string has no javascript: test";
    Boolean result = sanwaf.isThreat(value);
    assertFalse(result);
  }

  @Test
  public void testIsThreatMaxViolation() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    String value = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890 javascript: should fail";
    Boolean result = sanwaf.isThreat(value);
    assertTrue(result);
  }

  @Test
  public void testHasInvalidChildShield() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    Shield shield = UnitTestUtil.getShield(sanwaf, "xss-invalid-child-shield");
    assertTrue(shield.childShield == null);
  }

}

