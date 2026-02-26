package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ItemLengthsTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeAll
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf();
      shield = UnitTestUtil.getShield(sanwaf, "XSS");
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
    assertFalse(shield.threat(req, shield.parameters, "lengthN_0_5", "12345"));
    assertFalse(shield.threat(req, shield.parameters, "lengthN_0_5", "12345"));
    assertFalse(shield.threat(req, shield.parameters, "lengthN_0_5", "-1234"));
    assertTrue(shield.threat(req, shield.parameters, "lengthN_0_5", "123456"));

    assertFalse(shield.threat(req, shield.parameters, "lengthN2_0_5", "12345"));
    assertFalse(shield.threat(req, shield.parameters, "lengthN2_0_5", "-1234"));
    assertTrue(shield.threat(req, shield.parameters, "lengthN2_0_5", "123456"));
  }

  @Test
  public void testNumericDelimited()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "lengthNN_6_6", "123456"));
    assertFalse(shield.threat(req, shield.parameters, "lengthNN_6_6", "-12345"));
    assertFalse(shield.threat(req, shield.parameters, "lengthNN_6_6", "123456,123456"));
    assertTrue(shield.threat(req, shield.parameters, "lengthNN_6_6", "+123456"));
    assertTrue(shield.threat(req, shield.parameters, "lengthNN_6_6", "1234567"));
    assertTrue(shield.threat(req, shield.parameters, "lengthNN_6_6", "1234"));

    assertFalse(shield.threat(req, shield.parameters, "lengthNN2_6_6", "123456"));
    assertFalse(shield.threat(req, shield.parameters, "lengthNN2_6_6", "-12345"));
    assertFalse(shield.threat(req, shield.parameters, "lengthNN2_6_6", "123456,123456"));
    assertTrue(shield.threat(req, shield.parameters, "lengthNN2_6_6", "+123456"));
    assertTrue(shield.threat(req, shield.parameters, "lengthNN2_6_6", "1234567"));
    assertTrue(shield.threat(req, shield.parameters, "lengthNN2_6_6", "1234"));
  }

  @Test
  public void testAlphanumeric()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "lengthA_0_3", "ab1"));
    assertTrue(shield.threat(req, shield.parameters, "lengthA_0_3", "abc4"));

    assertFalse(shield.threat(req, shield.parameters, "lengthA2_0_3", "ab1"));
    assertTrue(shield.threat(req, shield.parameters, "lengthA2_0_3", "abc4"));
  }

  @Test
  public void testAlphanumericAndMore()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "lengthAA_0_4", "abc1"));
    assertFalse(shield.threat(req, shield.parameters, "lengthAA_0_4", "ab:1"));
    assertFalse(shield.threat(req, shield.parameters, "lengthAA_0_4", "a:2:"));
    assertTrue(shield.threat(req, shield.parameters, "lengthAA_0_4", "123456"));
    assertTrue(shield.threat(req, shield.parameters, "lengthAA_0_4", "12:346"));

    assertFalse(shield.threat(req, shield.parameters, "lengthAA2_0_4", "abc1"));
    assertFalse(shield.threat(req, shield.parameters, "lengthAA2_0_4", "ab:1"));
    assertFalse(shield.threat(req, shield.parameters, "lengthAA2_0_4", "a:2:"));
    assertTrue(shield.threat(req, shield.parameters, "lengthAA2_0_4", "123456"));
    assertTrue(shield.threat(req, shield.parameters, "lengthAA2_0_4", "12:346"));
  }

  @Test
  public void testChar()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "lengthC_1_1", "a"));
    assertFalse(shield.threat(req, shield.parameters, "lengthC_1_1", "1"));
    assertFalse(shield.threat(req, shield.parameters, "lengthC_1_1", "-"));
    assertFalse(shield.threat(req, shield.parameters, "lengthC_1_1", " "));
    assertTrue(shield.threat(req, shield.parameters, "lengthC_1_1", "12"));
    assertTrue(shield.threat(req, shield.parameters, "lengthC_1_1", "12345"));
    assertTrue(shield.threat(req, shield.parameters, "lengthC_1_1", "<asdffff."));

    assertFalse(shield.threat(req, shield.parameters, "lengthC2_1_1", "a"));
    assertFalse(shield.threat(req, shield.parameters, "lengthC2_1_1", "1"));
    assertFalse(shield.threat(req, shield.parameters, "lengthC2_1_1", "-"));
    assertFalse(shield.threat(req, shield.parameters, "lengthC2_1_1", " "));
    assertTrue(shield.threat(req, shield.parameters, "lengthC2_1_1", "12"));
    assertTrue(shield.threat(req, shield.parameters, "lengthC2_1_1", "12345"));
    assertTrue(shield.threat(req, shield.parameters, "lengthC2_1_1", "<asdffff."));
  }

  @Test
  public void testCustomRegex()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "lengthR_0_11", "555-55-5555"));
    assertTrue(shield.threat(req, shield.parameters, "lengthR_0_11", "abc-de-fghi1"));

    assertFalse(shield.threat(req, shield.parameters, "lengthR2_0_11", "555-55-5555"));
    assertTrue(shield.threat(req, shield.parameters, "lengthR2_0_11", "abc-de-fghi1"));
  }

  @Test
  public void testStringType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertTrue(shield.threat(req, shield.parameters, "lengthS2_0_7", "12345678"));

    assertFalse(shield.threat(req, shield.parameters, "lengthS_0_7", "1234567"));
    assertTrue(shield.threat(req, shield.parameters, "lengthS_0_7", "12345678"));

    assertFalse(shield.threat(req, shield.parameters, "lengthS2_0_7", "1234567"));
    assertTrue(shield.threat(req, shield.parameters, "lengthS2_0_7", "12345678"));

    assertFalse(shield.threat(req, shield.parameters, "lengthS_0_7", "1234567"));
    assertTrue(shield.threat(req, shield.parameters, "lengthS_0_7", "12345678"));

    assertFalse(shield.threat(req, shield.parameters, "lengthS2_0_7", "1234567"));
    assertTrue(shield.threat(req, shield.parameters, "lengthS2_0_7", "12345678"));
  }

  @Test
  public void testStringTypeMinSetNoValue()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertTrue(shield.threat(req, shield.parameters, "lengthNN2_6_6", ""));
    assertFalse(shield.threat(req, shield.parameters, "lengthNN2_6_6", null));
  }

  @Test
  public void TestMaxMinLength()
  {
    Shield shield = UnitTestUtil.getShield(sanwaf, "ParmLength");
    assertEquals(Integer.MAX_VALUE, shield.maxLen);
    assertEquals(0, shield.minLen);
    assertEquals(Integer.MAX_VALUE, shield.regexMinLen);

    Item p = shield.getItem(shield.parameters, "MaxMinLen");
    assertEquals(Integer.MAX_VALUE, p.max);
    assertEquals(0, p.min);
  }
}

