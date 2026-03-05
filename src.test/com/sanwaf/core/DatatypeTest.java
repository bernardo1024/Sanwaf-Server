package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;
import java.util.Calendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class DatatypeTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeAll
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf();
      shield = UnitTestUtil.getShield(sanwaf, "xss");
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
    assertFalse(shield.threat(req, shield.parameters, "Numeric", "0123456789"));
    assertFalse(shield.threat(req, shield.parameters, "Numeric", "-12345"));
    assertFalse(shield.threat(req, shield.parameters, "Numeric", "-12345.67"));
    assertTrue(shield.threat(req, shield.parameters, "Numeric", "foo.12"));
    assertTrue(shield.threat(req, shield.parameters, "Numeric", "12.bar"));
    assertTrue(shield.threat(req, shield.parameters, "Numeric", "12.34.56.78"));
    assertTrue(shield.threat(req, shield.parameters, "Numeric", "- 12345.67"));
    assertFalse(shield.threat(req, shield.parameters, "Numeric", null));
    assertFalse(shield.threat(req, shield.parameters, "Numeric", ""));
    assertFalse(shield.threat(req, shield.parameters, "NumericRequired", null));
    assertTrue(shield.threat(req, shield.parameters, "NumericRequired", ""));
    assertFalse(shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", ""));
    assertFalse(shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "10"));
    assertFalse(shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "2"));
    assertFalse(shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "5"));
    assertTrue(shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "11"));
    assertTrue(shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "1"));
    assertTrue(shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "abc"));
  }

  @Test
  public void testInteger()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "Integer", "12345"));
    assertFalse(shield.threat(req, shield.parameters, "Integer", "0123456789"));
    assertFalse(shield.threat(req, shield.parameters, "Integer", "-12345"));
    assertTrue(shield.threat(req, shield.parameters, "Integer", "-12345.67"));
    assertTrue(shield.threat(req, shield.parameters, "Integer", "foo.12"));
    assertTrue(shield.threat(req, shield.parameters, "Integer", "12.bar"));
    assertTrue(shield.threat(req, shield.parameters, "Integer", "12.34.56.78"));
    assertTrue(shield.threat(req, shield.parameters, "Integer", "- 12345"));
    assertTrue(shield.threat(req, shield.parameters, "Integer", " 12345"));
  }

  @Test
  public void testNumericDelimitedType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "n{}", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemNumericDelimited p = new ItemNumericDelimited(id, false);
    assertTrue(p.inError(req, shield, "12,34,56", false, false));

    List<Point> list = p.getErrorPoints(shield, "");
    assertEquals(0, list.size());
    list = p.getErrorPoints(shield, null);
    assertEquals(0, list.size());
    list = p.getErrorPoints(shield, null);
    assertEquals(0, list.size());
  }

  @Test
  public void testNumericDelimitedInErrorNull()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "n{,}", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemNumericDelimited p = new ItemNumericDelimited(id, false);
    assertFalse(p.inError(req, shield, null, false, false));
  }

  @Test
  public void testIntegerDelimitedType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "i{}", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemNumericDelimited p = new ItemNumericDelimited(id, false);
    assertTrue(p.inError(req, shield, "12,34,56", false, false));

    List<Point> list = p.getErrorPoints(shield, "");
    assertEquals(0, list.size());
    list = p.getErrorPoints(shield, null);
    assertEquals(0, list.size());
    list = p.getErrorPoints(shield, null);
    assertEquals(0, list.size());
  }

  @Test
  public void testAlphanumeric()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "Alphanumeric", "abcdefghijklmnopqrstuvwxyz0123456789"));
    assertTrue(shield.threat(req, shield.parameters, "Alphanumeric", "1239.a"));
    assertTrue(shield.threat(req, shield.parameters, "Alphanumeric", "1239.a...."));
    assertTrue(shield.threat(req, shield.parameters, "Alphanumeric", "1239.abc"));
    assertFalse(shield.threat(req, shield.parameters, "Alphanumeric", null));
    assertFalse(shield.threat(req, shield.parameters, "Alphanumeric", ""));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericRequired", null));
    assertTrue(shield.threat(req, shield.parameters, "AlphanumericRequired", ""));
  }

  @Test
  public void testAlphanumericSizeError()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertTrue(shield.threat(req, shield.parameters, "AlphanumericSizeError", "123"));
    assertTrue(shield.threat(req, shield.parameters, "AlphanumericSizeError", "1234"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericSizeError", "12345"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericSizeError", "123456"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericSizeError", "1234567"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericSizeError", "12345678"));
    assertTrue(shield.threat(req, shield.parameters, "AlphanumericSizeError", "123456789"));
  }

  @Test
  public void testAlphanumericAndMore()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMore", "abcde"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMore", "1?234"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMore", "1?a1b2c?3d4"));
    assertTrue(shield.threat(req, shield.parameters, "AlphanumericAndMore", "123-456"));
    assertTrue(shield.threat(req, shield.parameters, "AlphanumericAndMore", "123_456"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMore", ""));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMore", null));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMoreRequired", null));
    assertTrue(shield.threat(req, shield.parameters, "AlphanumericAndMoreRequired", ""));
  }

  @Test
  public void testAlphanumericAndMoreInvalidConfig()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMoreInvalidConfig1", "abc123? :"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMoreInvalidConfig2", "1?234"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMoreInvalidConfig3", "1?a1b2c?3d4"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMoreInvalidConfig4", "abc123"));
  }

  @Test
  public void testAlphanumericGetErrorPointsAllValid()
  {
    ItemAlphanumeric p = new ItemAlphanumeric(new ItemData(shield, "test", Modes.BLOCK, "", "a", "", "", Integer.MAX_VALUE, 0));
    List<Point> list = p.getErrorPoints(shield, "abcde");
    assertEquals(0, list.size());
  }

  @Test
  public void testAlphanumericGetErrorPointsMiddleError()
  {
    ItemAlphanumeric p = new ItemAlphanumeric(new ItemData(shield, "test", Modes.BLOCK, "", "a", "", "", Integer.MAX_VALUE, 0));
    List<Point> list = p.getErrorPoints(shield, "abc??de");
    assertEquals(1, list.size());
    assertEquals(3, list.get(0).start);
    assertEquals(5, list.get(0).end);
  }

  @Test
  public void testAlphanumericGetErrorPointsTrailingError()
  {
    ItemAlphanumeric p = new ItemAlphanumeric(new ItemData(shield, "test", Modes.BLOCK, "", "a", "", "", Integer.MAX_VALUE, 0));
    List<Point> list = p.getErrorPoints(shield, "abc??");
    assertEquals(1, list.size());
    assertEquals(3, list.get(0).start);
    assertEquals(5, list.get(0).end);
  }

  @Test
  public void testAlphanumericGetErrorPointsAllInvalid()
  {
    ItemAlphanumeric p = new ItemAlphanumeric(new ItemData(shield, "test", Modes.BLOCK, "", "a", "", "", Integer.MAX_VALUE, 0));
    List<Point> list = p.getErrorPoints(shield, "??");
    assertEquals(1, list.size());
    assertEquals(0, list.get(0).start);
    assertEquals(2, list.get(0).end);
  }

  @Test
  public void testAlphanumericAndMoreType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "a{,}", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemAlphanumericAndMore p = new ItemAlphanumericAndMore(id);
    assertFalse(p.inError(req, shield, "", false, false));
    assertFalse(p.inError(req, shield, "abcde", false, false));
    assertTrue(p.inError(req, shield, "abcde?fg", false, false));

    List<Point> list = p.getErrorPoints(shield, "abcde?fg");
    assertEquals(1, list.size());
    list = p.getErrorPoints(shield, "");
    assertEquals(0, list.size());
    list = p.getErrorPoints(shield, null);
    assertEquals(0, list.size());
    list = p.getErrorPoints(shield, "1239.xyz");
    assertEquals(1, list.size());
  }

  @Test
  public void testAlphanumericAndMoreTypeSpecialChars()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMoreSpecialChars", "a b\tc\nd\re"));
    assertTrue(shield.threat(req, shield.parameters, "AlphanumericAndMoreSpecialChars", "a \\"));
  }

  @Test
  public void testAlphanumericAndMoreTypeCurlyBraces()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMoreCurlyBraces", "{a}"));
  }

  @Test
  public void testChar()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "Char", "a"));
    assertFalse(shield.threat(req, shield.parameters, "Char", "1"));
    assertFalse(shield.threat(req, shield.parameters, "Char", "-"));
    assertFalse(shield.threat(req, shield.parameters, "Char", " "));
    assertTrue(shield.threat(req, shield.parameters, "Char", "12"));
    assertTrue(shield.threat(req, shield.parameters, "Char", "123456"));
    assertTrue(shield.threat(req, shield.parameters, "Char", "<asdffff."));
    assertFalse(shield.threat(req, shield.parameters, "Char", ""));
    assertFalse(shield.threat(req, shield.parameters, "Char", null));
    assertTrue(shield.threat(req, shield.parameters, "CharRequired", ""));
    assertFalse(shield.threat(req, shield.parameters, "CharRequired", null));

    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "c", "error msg1", null, 1, 0);
    ItemChar p = new ItemChar(id);
    assertTrue(p.inError(req, shield, "12345", false, false));
    assertFalse(p.inError(req, shield, "1", false, false));
    assertFalse(p.inError(req, shield, "", false, false));
    assertFalse(p.inError(req, shield, null, false, false));
  }

  @Test
  public void testCharGetErrorPointsNull()
  {
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "c", "error msg1", null, 1, 0);
    ItemChar p = new ItemChar(id);
    List<Point> points = p.getErrorPoints(shield, null);
    assertEquals(0, points.size());
  }

  @Test
  public void testOpen()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "Open", "a"));
    assertFalse(shield.threat(req, shield.parameters, "Open", "1 "));
    assertFalse(shield.threat(req, shield.parameters, "Open", "-a"));
    assertFalse(shield.threat(req, shield.parameters, "Open", "%$"));
    assertFalse(shield.threat(req, shield.parameters, "Open", ")9)_!@#$%^&*()_+=-`1234567890-=[]\\{>?>?<,./}|"));
    assertFalse(shield.threat(req, shield.parameters, "Open", "1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./"));
    assertFalse(shield.threat(req, shield.parameters, "Open", "<asdffff."));
    assertFalse(shield.threat(req, shield.parameters, "Open", ""));
    assertFalse(shield.threat(req, shield.parameters, "Open", null));
    assertTrue(shield.threat(req, shield.parameters, "OpenRequired", ""));
    assertFalse(shield.threat(req, shield.parameters, "OpenRequired", null));

    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "o", "error msg1", null, 10, 0);
    ItemOpen p = new ItemOpen(id);
    assertFalse(p.inError(req, shield, "12345", false, false));
    assertFalse(p.inError(req, shield, "1", false, false));
    assertFalse(p.inError(req, shield, "", false, false));
    assertFalse(p.inError(req, shield, null, false, false));
    assertTrue(p.inError(req, shield, "1234567890123", false, false));
  }

  @Test
  public void testOpenErrorPoints()
  {
    // <item><name>openErrorPoints</name><type>o</type><max>5</max><min>5</min></item>
    // <item><name>openErrorPointsMask</name><type>o</type><max>5</max><min>5</min><mask-err>***</mask-err></item>
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertTrue(shield.threat(req, shield.parameters, "openErrorPoints", "123456"));
    String s = Sanwaf.getErrors(req);
    assertTrue(s != null && s.contains("\"value\":\"123456\"") && s.contains("\"samplePoints\":"));

    req = new MockHttpServletRequest();
    assertTrue(shield.threat(req, shield.parameters, "openErrorPointsMask", "123456"));
    s = Sanwaf.getErrors(req);
    assertTrue(s != null && s.contains("\"value\":\"***\""));
  }

  @Test
  public void testRegex()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "CustomRegexSSN", "555-55-5555"));
    assertTrue(shield.threat(req, shield.parameters, "CustomRegexSSN", "abc-de-fghi"));
    assertTrue(shield.threat(req, shield.parameters, "CustomRegexSSN", "5555555555"));

    assertFalse(shield.threat(req, shield.parameters, "CustomTel", "555-555-5555"));
    assertTrue(shield.threat(req, shield.parameters, "CustomTel", "55-555-55556"));

    assertTrue(shield.threat(req, shield.parameters, "CustomDate", "20160101"));
    assertFalse(shield.threat(req, shield.parameters, "CustomDate", "2016-01-01"));

    assertFalse(shield.threat(req, shield.parameters, "lengthR_0_11", "555-55-5555"));
    assertTrue(shield.threat(req, shield.parameters, "lengthR_0_11", "abc-de-fghi"));

    assertFalse(shield.threat(req, shield.parameters, "lengthR2_0_11", "555-55-5555"));
    assertTrue(shield.threat(req, shield.parameters, "lengthR2_0_11", "abc-de-fghi"));
    assertTrue(shield.threat(req, shield.parameters, "lengthR2_0_11", "555-55-55"));
    assertTrue(shield.threat(req, shield.parameters, "lengthR2_0_11", "555-55-5555-55"));

    assertFalse(shield.threat(req, shield.parameters, "Regex", ""));
    assertFalse(shield.threat(req, shield.parameters, "Regex", null));
    assertTrue(shield.threat(req, shield.parameters, "RegexRequired", ""));
    assertFalse(shield.threat(req, shield.parameters, "RegexRequired", null));
  }

  @Test
  public void testRegexType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "r{telephone}", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemRegex p = new ItemRegex(id);
    assertTrue(p.patternName != null && !p.patternName.isEmpty());

    assertFalse(p.inError(req, shield, "416-555-5555", false, false));
    assertTrue(p.inError(req, shield, "abc-def-ghij", false, false));
    assertTrue(p.inError(req, shield, "a", false, false));
    assertTrue(p.inError(req, shield, "abc-def-ghij-klmn", false, false));

    List<Point> list = p.getErrorPoints(shield, "");
    assertEquals(0, list.size());
    list = p.getErrorPoints(shield, null);
    assertEquals(0, list.size());
    list = p.getErrorPoints(shield, "416-555-5555");
    assertEquals(0, list.size());
    list = p.getErrorPoints(shield, "abc123def456");
    assertEquals(1, list.size());
  }

  @Test
  public void testRegexTypeInvalidFormta()
  {
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "r telephone", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemRegex p = new ItemRegex(id);
    assertNull(p.patternName);
    assertNull(p.rule);
  }

  @Test
  public void testRegexTypeNonExistentPattern()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "r{nonExistentPattern}", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemRegex p = new ItemRegex(id);
    assertFalse(p.inError(req, shield, "anyvalue", false, false));
  }

  @Test
  public void testConstantType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "Constant", "FOO"));
    assertFalse(shield.threat(req, shield.parameters, "Constant", "BAR"));
    assertFalse(shield.threat(req, shield.parameters, "Constant", "FAR"));
    assertFalse(shield.threat(req, shield.parameters, "Constant", null));
    assertFalse(shield.threat(req, shield.parameters, "Constant", ""));
    assertFalse(shield.threat(req, shield.parameters, "ConstantRequired", null));
    assertTrue(shield.threat(req, shield.parameters, "ConstantRequired", ""));
    assertTrue(shield.threat(req, shield.parameters, "Constant", "foo"));
    assertTrue(shield.threat(req, shield.parameters, "Constant", "bar"));
    assertTrue(shield.threat(req, shield.parameters, "Constant", "far"));
    assertTrue(shield.threat(req, shield.parameters, "Constant", "FOOO"));

    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "rk FOO,BAR", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemConstant p = new ItemConstant(id);
    assertTrue(p.constants.isEmpty());
    id = new ItemData(shield, "key1", Modes.BLOCK, "", "k FOO}", "error msg1", null, Integer.MAX_VALUE, 0);
    p = new ItemConstant(id);
    assertTrue(p.constants.isEmpty());

    id = new ItemData(shield, "key1", Modes.BLOCK, "", "", "error msg1", null, Integer.MAX_VALUE, 0);
    p = new ItemConstant(id);
    assertTrue(p.constants.isEmpty());
  }

  @Test
  public void testConstantTypeNonExistentConstants()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "rk FOO,BAR", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemConstant p = new ItemConstant(id);
    assertTrue(p.constants.isEmpty());
    assertTrue(p.inError(req, shield, "anyvalue", false, false));
    assertFalse(p.inError(req, shield, "", false, false));
    assertFalse(p.inError(req, shield, null, false, false));
    String props = p.getProperties();
    assertNotNull(props);
  }

  @Test
  public void testPoint()
  {
    Point p = new Point(1, 100);
    assertTrue(p.toString().contains("start: 1, end: 100"));
  }

  @Test
  public void testJava()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertTrue(shield.threat(req, shield.parameters, "Java", "12345"));
    assertTrue(shield.threat(req, shield.parameters, "Java", "12345678901"));// violates
    // max
    // setting
    assertFalse(shield.threat(req, shield.parameters, "Java", ""));
    assertFalse(shield.threat(req, shield.parameters, "JavaRequired", null));
    assertTrue(shield.threat(req, shield.parameters, "JavaRequired", ""));
    assertFalse(shield.threat(req, shield.parameters, "Java", "10"));
    assertFalse(shield.threat(req, shield.parameters, "Java", null));
    assertFalse(shield.threat(req, shield.parameters, "Java", "0001"));
    assertFalse(shield.threat(req, shield.parameters, "Java", "0000"));
  }

  @Test
  public void parseMethodNameTest()
  {
    assert (ItemJava.parseMethod("foo.method()").equals("method"));
    assert (ItemJava.parseMethod("foomethod()").equals("foomethod()"));
  }

  @Test
  public void testJavaMultipleParms()
  {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("JavaMultiParm", "foobarfoobar");
    request.addParameter("JavaMultiParm2", "foobarfoobar");
    request.addParameter("JavaMultiParm3", "foobarfoobar");
    boolean result = sanwaf.isThreatDetected(request);
    assertFalse(result);

    request = new MockHttpServletRequest();
    request.addParameter("JavaMultiParm", "foobarfoobar");
    request.addParameter("JavaMultiParm2", "foobarfoobar");
    request.addParameter("JavaMultiParm3", "foobar");
    result = sanwaf.isThreatDetected(request);
    assertTrue(result);

    request = new MockHttpServletRequest();
    request.addParameter("JavaMultiParm", "foobarfoobar");
    request.addParameter("JavaMultiParm2", "foobar");
    request.addParameter("JavaMultiParm3", "foobarfoobar");
    result = sanwaf.isThreatDetected(request);
    assertTrue(result);

    request = new MockHttpServletRequest();
    request.addParameter("JavaMultiParm", "foobar");
    request.addParameter("JavaMultiParm2", "foobarfoobar");
    request.addParameter("JavaMultiParm3", "foobarfoobar");
    result = sanwaf.isThreatDetected(request);
    assertTrue(result);
  }

  @Test
  public void testJavaInvalidClass()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    boolean b = shield.threat(req, shield.parameters, "JavaInvalidClass", "0000");
    assertTrue(b);

    req = new MockHttpServletRequest();
    b = shield.threat(req, shield.parameters, "JavaInvalidClass2", "0000");
    assertTrue(b);

    req = new MockHttpServletRequest();
    b = shield.threat(req, shield.parameters, "JavaInvalidClassEmpty", "0000");
    assertTrue(b);

    req = new MockHttpServletRequest();
    b = shield.threat(req, shield.parameters, "JavaInvalidClassNoPackage", "0000");
    assertTrue(b);
  }

  @Test
  public void testJavaInvalidMethod()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    boolean b = shield.threat(req, shield.parameters, "JavaInvalidMethod", "0000");
    assertFalse(b);
  }

  @Test
  public void testFormatType()
  {
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "f{(###) ###-####", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemFormat p = new ItemFormat(id);
    assertNotNull(p.formatString);
    assertFalse(p.formatString.isEmpty());
  }

  @Test
  public void testInvalidFormatType()
  {
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "f {(###) ###-####", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemFormat p = new ItemFormat(id);
    assertNull(p.formatString);
  }

  @Test
  public void testFormat()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "parmformat", "(123) 456-7890 abc ABC"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat", "BAR"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat", ""));
    assertFalse(shield.threat(req, shield.parameters, "parmformat", null));
  }

  @Test
  public void testFormatRequired()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "parmFormatRequired", "(123) 456-7890 abc ABC"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired", "BAR"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired", ""));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatRequired", null));
  }

  @Test
  public void testFormat2Required()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0ZzZ"));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Zzz"));

    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", " Aac 0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "{Aac 0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "-Aac 0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "# ac 0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#{ac 0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#-ac 0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#A c 0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#A{c 0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#A-c 0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aa  0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aa{ 0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aa- 0Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac zZzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac {Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac -Zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0zzz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0{zz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0-zz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 00zz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Z0z"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0ZZz"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Z{z"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Z-z"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Zz "));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Zz0"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Zz{"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Zz-"));

    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", "BAR"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatRequired2", ""));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatRequired2", null));
  }

  @Test
  public void testFormat2()
  {
    // <item><name>parmformat2</name><type>f{#[1-12] / #[21-35]}</type>
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "parmformat2", "12 / 30"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2", "01 / 30"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2", "12 / 21"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2", "12 / 35"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2", "11 / 29"));

    assertTrue(shield.threat(req, shield.parameters, "parmformat2", "a0 / 25"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2", "z0 / 25"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2", "/0 / 25"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2", ":0 / 25"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2", "00 / 25"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2", "13 / 25"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2", "93 / 25"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2", "01 / 20"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2", "01 / 36"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2", "01 / 99"));

    assertTrue(shield.threat(req, shield.parameters, "parmformat2", "0z / 9b"));

    assertFalse(shield.threat(req, shield.parameters, "parmformat2", ""));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2", null));
  }

  @Test
  public void testFormat2brackets()
  {
    // <item><name>parmformat2brackets</name><type>f{\[\]#[1-10]}</type>
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "parmformat2brackets", "[]01"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2brackets", "[]02"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2brackets", "[]03"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2brackets", "[]04"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2brackets", "[]05"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2brackets", "[]06"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2brackets", "[]07"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2brackets", "[]08"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2brackets", "[]09"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat2brackets", "[]10"));

    assertTrue(shield.threat(req, shield.parameters, "parmformat2brackets", "[]00"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2brackets", "[]99"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2brackets", " ]01"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat2brackets", "[ 01"));

    // <item><name>parmformat3</name><type>f{#[1-9]}</type>
    assertFalse(shield.threat(req, shield.parameters, "parmformat3", "1"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat3", "2"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat3", "3"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat3", "4"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat3", "5"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat3", "6"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat3", "7"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat3", "8"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat3", "9"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat3", "10"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat3", "0"));

    // <item><name>parmformat4</name><type>f{#[3,4,5,6]###-####-####-####}</type></item>
    assertFalse(shield.threat(req, shield.parameters, "parmformat4", "3123-1234-1234-1234"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat4", "4123-1234-1234-1234"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat4", "5123-1234-1234-1234"));
    assertFalse(shield.threat(req, shield.parameters, "parmformat4", "6123-1234-1234-1234"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat4", "1123-1234-1234-1234"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat4", "2123-1234-1234-1234"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat4", "7123-1234-1234-1234"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat4", "8123-1234-1234-1234"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat4", "9123-1234-1234-1234"));
    assertTrue(shield.threat(req, shield.parameters, "parmformat4", "9123-1234-1234-12"));

  }

  @Test
  public void testBadFormats()
  {
    // <item><name>parmformat2brackets</name><type>f{\[\]#[1-10]}</type>
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "parmbadformat1", "@"));
    assertFalse(shield.threat(req, shield.parameters, "parmbadformat2", "@"));
    assertFalse(shield.threat(req, shield.parameters, "parmbadformat3", "@"));
    assertFalse(shield.threat(req, shield.parameters, "parmbadformat4", "@"));
  }

  @Test
  public void testMultiFormats()
  {
    // <item><name>parmMultiFormat1</name><type>f{#####||#####-####}</type></item>
    // <item><name>parmMultiFormat2</name><type>f{#####||#####-####||A#A-#A#}</type></item>
    // <item><name>parmMultiFormat3</name><type>f{#####||#####-####||A#A-#A#||A##
    // A###}</type></item>
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "parmMultiFormat1", "12345"));
    assertFalse(shield.threat(req, shield.parameters, "parmMultiFormat1", "12345-6789"));
    assertTrue(shield.threat(req, shield.parameters, "parmMultiFormat1", "@"));

    assertFalse(shield.threat(req, shield.parameters, "parmMultiFormat2", "12345"));
    assertFalse(shield.threat(req, shield.parameters, "parmMultiFormat2", "12345-6789"));
    assertFalse(shield.threat(req, shield.parameters, "parmMultiFormat2", "A1B-2C3"));
    assertTrue(shield.threat(req, shield.parameters, "parmMultiFormat2", "@"));

    assertFalse(shield.threat(req, shield.parameters, "parmMultiFormat3", "12345"));
    assertFalse(shield.threat(req, shield.parameters, "parmMultiFormat3", "12345-6789"));
    assertFalse(shield.threat(req, shield.parameters, "parmMultiFormat3", "A1B-2C3"));
    assertFalse(shield.threat(req, shield.parameters, "parmMultiFormat3", "A12 B345"));
    assertTrue(shield.threat(req, shield.parameters, "parmMultiFormat3", "A12 B5"));

    assertFalse(shield.threat(req, shield.parameters, "parmMultiFormatInvalid", "A12 B5"));
  }

  @Test
  public void testDependentFormats()
  {
    // <item><name>depformatParent</name><type></type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>depformat</name><type>d{depformatParent:US=#####;Canada=A#A-#A#}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>depformatMultiple</name><type>d{depformatParent:US=#####||#####-####;Canada=A#A-#A#}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>depformatRequired</name><type>d{depformatParent:US=#####||#####-####;Canada=A#A-#A#}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req>true</req><related></related></item>
    // <item><name>depformatInvalidFormatBadParent</name><type>d{foobar:US=#####||#####-####;Canada=A#A-#A#}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>depformatInvalidFormat</name><type>d{depformatParent:US=#####||#####-####;Canada=A#A-#A#</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>depformatInvalidFormat1</name><type>d{depformatParent:US=}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>depformatInvalidFormat2</name><type>d{depformatParent}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformat", "12345");
    boolean result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformat", "A1A-1A1");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "Canada");
    req.addParameter("depformat", "A1A-1A1");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "Canada");
    req.addParameter("depformat", "12345");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatMultiple", "12345-1234");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatMultiple", "A1A-1A1");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "xxxxx");
    req.addParameter("depformatMultiple", "A1A-1A1");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatMultiple", "1234");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatMultiple", "12345-123");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatRequired", "12345");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatRequired", "");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormatBadParent", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat1", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat2", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat3", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat4", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat5", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat6", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat7", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat8", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat9", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertFalse(result);
  }

  @Test
  public void testDepFormatType()
  {
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "d {depformatParent:US=#####;Canada=A#A-#A#", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemDependentFormat p = new ItemDependentFormat(id);
    assertNull(p.dependentElementName);
    assertNull(p.depFormatString);
    assertEquals(0, p.formats.size());

    id = new ItemData(shield, "key1", Modes.BLOCK, "", "d{depformatParent:US=#####;Canada=A#A-#A#}", "error msg1", null, Integer.MAX_VALUE, 0);
    p = new ItemDependentFormat(id);
    assertEquals("depformatParent", p.dependentElementName);
    assertEquals("depformatParent:US=#####;Canada=A#A-#A#", p.depFormatString);
    assertEquals(2, p.formats.size());
  }

  @Test
  public void testDependentFormatModifyErrorMsgNullDepName()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "d{noColon}", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemDependentFormat p = new ItemDependentFormat(id);
    assertNull(p.dependentElementName);
    String result = p.modifyErrorMsg(req, "some error");
    assertNotNull(result);
  }

  @Test
  public void testFormatStrictErrorJsonNull()
  {
    String json = JsonFormatter.formatStrictErrorJson(null);
    assertTrue(json.contains("\"value\":\"\""));
    assertFalse(json.contains("\"value\":\"null\""));
  }

  @Test
  public void testToJsonNullValue()
  {
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "c", "error msg1", null, 1, 0);
    ItemChar item = new ItemChar(id);
    String json = JsonFormatter.toJson(item, null, Modes.BLOCK, null, false, null, null);
    assertTrue(json.contains("\"value\":\"\""));
    assertFalse(json.contains("\"value\":\"null\""));
  }

  @Test
  public void testFormatEscapeChars()
  {
    // <item><name>parmformatEscapedChars</name><type>f{\#\A\a\c\x\[\]\(\)\|\:\=\+\-\;#}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>parmformatEscapedXchar1</name><type>f{xxx}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>parmformatEscapedXchar2</name><type>f{xxx
    // #}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>parmformatEscapedXchar3</name><type>f{xxx
    // A}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>parmformatEscapedXchar4</name><type>f{xxx
    // a}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>parmformatEscapedXchar5</name><type>f{xxx
    // c}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>
    // <item><name>parmformatEscapedXchar6</name><type>f{xxx
    // #[1-3]}</type><max></max><min></min><max-value></max-value><min-value></min-value><msg></msg><req></req><related></related></item>

    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "parmformatEscapedChars", "#Aacx[]()|:=+-;1"));
    assertTrue(shield.threat(req, shield.parameters, "parmMultiFormat3", "A12 B5"));

    assertFalse(shield.threat(req, shield.parameters, "parmformatEscapedXchar1", "!@#"));
    assertFalse(shield.threat(req, shield.parameters, "parmformatEscapedXchar2", "a9$ 9"));
    assertFalse(shield.threat(req, shield.parameters, "parmformatEscapedXchar3", "a9$ A"));
    assertFalse(shield.threat(req, shield.parameters, "parmformatEscapedXchar4", "a9$ a"));
    assertFalse(shield.threat(req, shield.parameters, "parmformatEscapedXchar5", "a9$ x"));
    assertFalse(shield.threat(req, shield.parameters, "parmformatEscapedXchar5", "a9$ X"));
    assertFalse(shield.threat(req, shield.parameters, "parmformatEscapedXchar6", "a9$ 1"));

    assertTrue(shield.threat(req, shield.parameters, "parmformatEscapedXchar1", "!@# "));
    assertTrue(shield.threat(req, shield.parameters, "parmformatEscapedXchar2", "a9$ a"));
    assertTrue(shield.threat(req, shield.parameters, "parmformatEscapedXchar3", "a9$ a"));
    assertTrue(shield.threat(req, shield.parameters, "parmformatEscapedXchar4", "a9$ A"));
    assertTrue(shield.threat(req, shield.parameters, "parmformatEscapedXchar5", "a9$ 0"));
    assertTrue(shield.threat(req, shield.parameters, "parmformatEscapedXchar5", "a9$ 0"));
    assertTrue(shield.threat(req, shield.parameters, "parmformatEscapedXchar6", "a9$ 0"));
  }

  @Test
  public void testFormatsWithDates()
  {
    // <item><name>parmFormatWithDate1</name><type>f{#[yy-yy(+10)]}</type></item>
    // <item><name>parmFormatWithDate2</name><type>f{#[yyyy-yyyy(+10)]}</type></item>
    // <item><name>parmFormatWithDate3</name><type>f{#[dd-dd(+5)]}</type></item>
    // <item><name>parmFormatWithDate4</name><type>f{#[mm-mm(+5)]}</type></item>
    // <item><name>parmFormatWithDateInvalid5</name><type>f{#[yy-yy(+10]}</type></item>
    // <item><name>parmFormatWithDateInvalid6</name><type>f{dd-dd+5]}</type></item>
    // <item><name>parmFormatWithDateInvalid7</name><type>f{mm
    // mm(+5)}</type></item>
    // <item><name>parmFormatWithDateOverflowMonth</name><type>f{#[mm-mm(+12)]}</type></item>
    // <item><name>parmFormatWithDateOverflowDay</name><type>f{#[dd-dd(+31)]}</type></item>

    Calendar c = Calendar.getInstance();
    int yyyy = c.get(Calendar.YEAR);
    int yy = Integer.parseInt(String.valueOf(yyyy).substring(2));
    int dd = c.get(Calendar.DAY_OF_MONTH);
    int mm = c.get(Calendar.MONTH) + 1;

    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDateOverflowMonth", "12"));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDateOverflowDay", "31"));

    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDate1", String.valueOf(yy)));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDate1", String.valueOf(yy + 10)));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatWithDate1", String.valueOf(yy + 11)));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatWithDate1", String.valueOf(yy - 1)));

    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDate1a", String.valueOf(yy)));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDate1a", String.valueOf(yy - 10)));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatWithDate1a", String.valueOf(yy - 11)));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatWithDate1a", String.valueOf(yy + 1)));

    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDate2", String.valueOf(yyyy)));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDate2", String.valueOf(yyyy + 10)));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDate2a", String.valueOf(yyyy)));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDate2a", String.valueOf(yyyy - 10)));

    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDate3", String.valueOf(dd)));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatWithDate4", String.valueOf(mm)));

    // literal min, date max: #[1-dd]
    assertFalse(shield.threat(req, shield.parameters, "parmFormatDateLiteralMin", String.valueOf(dd)));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatDateLiteralMin", "0"));

    // date min, literal max: #[dd-31]
    assertFalse(shield.threat(req, shield.parameters, "parmFormatDateLiteralMax", "31"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatDateLiteralMax", "32"));

    // mixed date types on each side: #[dd-yyyy]
    assertFalse(shield.threat(req, shield.parameters, "parmFormatDateMixedTypes", String.valueOf(yyyy)));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatDateMixedTypes", String.valueOf(yyyy + 1)));

    // negative resolved min: #[yy(-200)-yy]
    assertFalse(shield.threat(req, shield.parameters, "parmFormatDateNegMin", String.valueOf(yy)));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatDateNegMin", String.valueOf(yy + 1)));
  }

  @Test
  public void testParmFormatIP()
  {
    // <item><name>parmFormatIP</name><type>f{#[0-255].#[0-255].#[0-255].#[0-255]}</type></item>
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertFalse(shield.threat(req, shield.parameters, "parmFormatIP", "111.111.111.111"));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatIP", "255.255.255.255"));
    assertFalse(shield.threat(req, shield.parameters, "parmFormatIP", "000.000.000.000"));

    assertTrue(shield.threat(req, shield.parameters, "parmFormatIP", "1.1.1.1"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatIP", "1.1.1.1"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatIP", "1"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatIP", "1.1.1"));
    assertTrue(shield.threat(req, shield.parameters, "parmFormatIP", "1"));
  }

  @Test
  public void testItemStrictNoNPE()
  {
    ItemStrict item = new ItemStrict("test value");
    assertNotNull(item.getErrorPoints(shield, "test"));
    assertTrue(item.getErrorPoints(shield, "test").isEmpty());
    assertEquals(Types.STRICT, item.getType());
  }

  @Test
  public void testItemStrictInErrorAlwaysFalse()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemStrict item = new ItemStrict("strict msg");
    assertFalse(item.inError(req, shield, "anything", false, false));
    assertFalse(item.inError(req, shield, "", false, false));
    assertFalse(item.inError(req, shield, null, false, false));
    assertFalse(item.inError(req, shield, "<script>alert(1)</script>", true, true));
  }

  @Test
  public void testItemStrictMsgStoredCorrectly()
  {
    ItemStrict item = new ItemStrict("custom error");
    assertEquals("custom error", item.msg);

    ItemStrict empty = new ItemStrict("");
    assertEquals("", empty.msg);

    ItemStrict nullMsg = new ItemStrict(null);
    assertNull(nullMsg.msg);
  }

  @Test
  public void testItemStrictGetErrorPointsWithEdgeCases()
  {
    ItemStrict item = new ItemStrict("msg");
    assertTrue(item.getErrorPoints(shield, null).isEmpty());
    assertTrue(item.getErrorPoints(shield, "").isEmpty());
    assertTrue(item.getErrorPoints(null, "value").isEmpty());
    assertTrue(item.getErrorPoints(null, null).isEmpty());
  }

  @Test
  public void testReplaceStringMultipleOccurrences()
  {
    assertEquals("a b ", ItemAlphanumericAndMore.replaceString("a\\sb\\s", "\\s", " "));
    assertEquals("a\tb\t", ItemAlphanumericAndMore.replaceString("a\\tb\\t", "\\t", "\t"));
  }

  @Test
  public void testGetMoreCharArrayMultipleSpecialChars()
  {
    char[] result = ItemAlphanumericAndMore.getMoreCharArray("-\\s.\\s");
    assertArrayEquals(new char[]{'-', ' ', '.', ' '}, result);
  }

  @Test
  public void testHandleSpecialCharsMultipleSpaces()
  {
    assertEquals("-<space>.<space>", ItemAlphanumericAndMore.handleSpecialChars(new char[]{'-', ' ', '.', ' '}));
  }

  @Test
  public void testIsSizeErrorNullRequiredDoesNotNPE()
  {
    Item item = new ItemAlphanumeric(new ItemData(shield, "test", Modes.BLOCK, "", "a", "", "", Integer.MAX_VALUE, 0));
    item.required = true;
    assertTrue(item.isSizeError(null));
  }

  @Test
  public void testIsSizeErrorNullNotRequired()
  {
    Item item = new ItemAlphanumeric(new ItemData(shield, "test", Modes.BLOCK, "", "a", "", "", Integer.MAX_VALUE, 0));
    item.required = false;
    assertFalse(item.isSizeError(null));
  }

}

