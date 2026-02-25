package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ErrorMessagesTest
{
  static Sanwaf sanwaf;
  static Shield shield;
  static Shield shieldBadPlaceholders;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-customErrors.xml");
      shield = UnitTestUtil.getShield(sanwaf, "XSS");
      shieldBadPlaceholders = UnitTestUtil.getShield(sanwaf, "BadPlaceholders");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void alpahnumericAndMoreDatatatypeErrorMsgTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "a{?}", "error msg1", null, Integer.MAX_VALUE, 2);
    ItemAlphanumericAndMore p = new ItemAlphanumericAndMore(id);
    String s = p.modifyErrorMsg(req, "some {0} String");
    assertTrue(s.contains("?"));
  }

  @Test
  public void numericDelimietedDatatatypeErrorMsgTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "n{,}", "error msg1", null, Integer.MAX_VALUE, 2);
    ItemNumericDelimited p = new ItemNumericDelimited(id, false);
    String s = p.modifyErrorMsg(req, "some {0} String");
    assertTrue(s.contains(","));
  }

  @Test
  public void constantDatatatypeErrorMsgTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "k{foo,bar,far}", "", null, Integer.MAX_VALUE, 0);
    ItemConstant p = new ItemConstant(id);
    String s = p.getErrorMessage(req, shield);
    assertTrue(s.contains("foo"));
  }
}

