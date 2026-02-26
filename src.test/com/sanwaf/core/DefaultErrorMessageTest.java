package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class DefaultErrorMessageTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-reduced.xml");
      shield = UnitTestUtil.getShield(sanwaf, "XSS");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void stringFallbackTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "s", "", null, Integer.MAX_VALUE, 0);
    ItemString item = new ItemString(id);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertEquals(ItemString.FAILED_PATTERN, err);
  }

  @Test
  public void numericFallbackTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "n", "", null, Integer.MAX_VALUE, 0);
    ItemNumeric item = new ItemNumeric(id, false);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertEquals(ItemNumeric.INVALID_NUMBER, err);
  }

  @Test
  public void alphanumericFallbackTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "a", "", null, Integer.MAX_VALUE, 0);
    ItemAlphanumeric item = new ItemAlphanumeric(id);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertEquals(ItemAlphanumeric.INVALID_AN, err);
  }

  @Test
  public void alphanumericAndMoreFallbackTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "a{? :}", "", null, Integer.MAX_VALUE, 0);
    ItemAlphanumericAndMore item = new ItemAlphanumericAndMore(id);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertEquals(ItemAlphanumericAndMore.INVALID_AN_MORE, err);
  }

  @Test
  public void charFallbackTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "c", "", null, Integer.MAX_VALUE, 0);
    ItemChar item = new ItemChar(id);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertEquals(ItemChar.INVALID_CHAR, err);
  }

  @Test
  public void constantFallbackTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "k{foo,bar}", "", null, Integer.MAX_VALUE, 0);
    ItemConstant item = new ItemConstant(id);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertEquals(ItemConstant.INVALID_CONSTANT, err);
  }

  @Test
  public void formatFallbackTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "f{###-###-####}", "", null, Integer.MAX_VALUE, 0);
    ItemFormat item = new ItemFormat(id);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertEquals(ItemFormat.INVALID_FORMAT, err);
  }

  @Test
  public void dependentFormatFallbackTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "d{depField:val1=###;val2=##-##}", "", null, Integer.MAX_VALUE, 0);
    ItemDependentFormat item = new ItemDependentFormat(id);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertEquals(ItemDependentFormat.INVALID_DEP_FORMAT, err);
  }

  @Test
  public void regexFallbackTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "r{somePattern}", "", null, Integer.MAX_VALUE, 0);
    ItemRegex item = new ItemRegex(id);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertEquals(ItemRegex.FAILED_CUSTOM_PATTERN, err);
  }

  @Test
  public void javaFallbackTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "j{com.sanwaf.core.JavaClass.over10trueElseFalse()}", "", null, Integer.MAX_VALUE, 0);
    ItemJava item = new ItemJava(id);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertEquals(ItemJava.INVALID_JAVA, err);
  }

  @Test
  public void perItemMsgTakesPrecedenceTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "n", "custom per-item msg", null, Integer.MAX_VALUE, 0);
    ItemNumeric item = new ItemNumeric(id, false);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertEquals("custom per-item msg", err);
  }

  @Test
  public void charFallbackSaysCharNotConstantTest()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "c", "", null, Integer.MAX_VALUE, 0);
    ItemChar item = new ItemChar(id);
    String err = JsonFormatter.getErrorMessage(item, req, shield);
    assertTrue(err.contains("Char"));
    assertTrue(!err.contains("Constant"));
  }
}
