package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ReduceXmlTest
{
  static Sanwaf sanwaf;

  @BeforeAll
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-reduced.xml");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void numericTest()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("Numeric", "abc123");
    boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result);

    request = new MockHttpServletRequest();
    request.addParameter("Numeric", "12345");
    result = sanwaf.isThreatDetected(request);
    assertFalse(result);
  }
}

