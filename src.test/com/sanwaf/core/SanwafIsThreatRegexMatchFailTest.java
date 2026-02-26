package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.MethodOrderer;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@TestMethodOrder(MethodOrderer.MethodName.class)
public class SanwafIsThreatRegexMatchFailTest
{
  static Sanwaf sanwaf;

  @BeforeAll
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-isThreatRegexMatchFail.xml");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testRegex()
  {
    assertFalse(sanwaf.isThreat("foobar"));
    assertTrue(sanwaf.isThreat("foo1bar"));
  }

}

