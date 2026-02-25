package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SanwafChildShieldTest
{
  static Sanwaf sanwaf;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-childShield.xml");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testHasChildShield()
  {
    Shield shield = UnitTestUtil.getShield(sanwaf, "xss");
    assertEquals("XSS-CHILD", shield.childShield.name);
  }

  @Test
  public void testChildShieldNoMaxViolationThreat()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("String", "javascript: should pass short string has no javascript: test");
    boolean result = sanwaf.isThreatDetected(request);
    assertFalse(result);
  }

  @Test
  public void testChildShieldMaxViolationThreat()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("String", "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890 javascript: should fail");
    boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);
  }

  @Test
  public void testIsThreatNoMaxViolation()
  {
    String value = "javascript: should pass short string has no javascript: test";
    boolean result = sanwaf.isThreat(value);
    assertFalse(result);
  }

  @Test
  public void testIsThreatMaxViolation()
  {
    String value = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890 javascript: should fail";
    boolean result = sanwaf.isThreat(value);
    assertTrue(result);
  }

  @Test
  public void testHasInvalidChildShield()
  {
    Shield shield = UnitTestUtil.getShield(sanwaf, "xss-invalid-child-shield");
    assertNull(shield.childShield);
  }

}

