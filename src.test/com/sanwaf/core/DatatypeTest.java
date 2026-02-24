package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;
import java.util.Calendar;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DatatypeTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf();
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    }
    catch (IOException ioe)
    {
      assertTrue(false);
    }
  }

  @Test
  public void testNumeric()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "lengthN_0_5", "12345", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Numeric", "0123456789", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Numeric", "-12345", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Numeric", "-12345.67", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Numeric", "foo.12", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Numeric", "12.bar", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Numeric", "12.34.56.78", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Numeric", "- 12345.67", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Numeric", null, false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Numeric", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "NumericRequired", null, false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "NumericRequired", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "10", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "2", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "5", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "11", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "1", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Numeric-maxval10-minval2", "abc", false, false));
  }

  @Test
  public void testInteger()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    // assertEquals(false, shield.threat(req, shield.parameters, "Integer",
    // "12345", false, false));
    // assertEquals(false, shield.threat(req, shield.parameters, "Integer",
    // "0123456789", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Integer", "-12345", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Integer", "-12345.67", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Integer", "foo.12", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Integer", "12.bar", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Integer", "12.34.56.78", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Integer", "- 12345", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Integer", " 12345", false, false));
  }

  @Test
  public void testNumericDelimitedType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "n{}", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemNumericDelimited p = new ItemNumericDelimited(id, false);
    assertEquals(true, p.inError(req, shield, "12,34,56", false, false));

    List<Point> list = p.getErrorPoints(shield, "");
    assertEquals(true, list.size() == 0);
    list = p.getErrorPoints(shield, null);
    assertEquals(true, list.size() == 0);
    list = p.getErrorPoints(shield, null);
    assertEquals(true, list.size() == 0);
  }

  @Test
  public void testIntegerDelimitedType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "i{}", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemNumericDelimited p = new ItemNumericDelimited(id, false);
    assertEquals(true, p.inError(req, shield, "12,34,56", false, false));

    List<Point> list = p.getErrorPoints(shield, "");
    assertEquals(true, list.size() == 0);
    list = p.getErrorPoints(shield, null);
    assertEquals(true, list.size() == 0);
    list = p.getErrorPoints(shield, null);
    assertEquals(true, list.size() == 0);
  }

  @Test
  public void testAlphanumeric()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "Alphanumeric", "abcdefghijklmnopqrstuvwxyz0123456789", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Alphanumeric", "1239.a", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Alphanumeric", "1239.a....", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Alphanumeric", "1239.abc", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Alphanumeric", null, false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Alphanumeric", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericRequired", null, false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "AlphanumericRequired", "", false, false));
  }

  @Test
  public void testAlphanumericSizeError()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(true, shield.threat(req, shield.parameters, "AlphanumericSizeError", "123", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "AlphanumericSizeError", "1234", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericSizeError", "12345", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericSizeError", "123456", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericSizeError", "1234567", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericSizeError", "12345678", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "AlphanumericSizeError", "123456789", false, false));
  }

  @Test
  public void testAlphanumericAndMore()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMore", "abcde", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMore", "1?234", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMore", "1?a1b2c?3d4", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "AlphanumericAndMore", "123-456", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "AlphanumericAndMore", "123_456", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMore", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMore", null, false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMoreRequired", null, false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "AlphanumericAndMoreRequired", "", false, false));
  }

  @Test
  public void testAlphanumericAndMoreInvalidConfig()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMoreInvalidConfig1", "abc123? :", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMoreInvalidConfig2", "1?234", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMoreInvalidConfig3", "1?a1b2c?3d4", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMoreInvalidConfig4", "abc123", false, false));
  }

  @Test
  public void testAlphanumericAndMoreType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "a{,}", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemAlphanumericAndMore p = new ItemAlphanumericAndMore(id);
    assertEquals(false, p.inError(req, shield, "", false, false));
    assertEquals(false, p.inError(req, shield, "abcde", false, false));
    assertEquals(true, p.inError(req, shield, "abcde?fg", false, false));

    List<Point> list = p.getErrorPoints(shield, "abcde?fg");
    assertEquals(true, list.size() == 1);
    list = p.getErrorPoints(shield, "");
    assertEquals(true, list.size() == 0);
    list = p.getErrorPoints(shield, null);
    assertEquals(true, list.size() == 0);
    list = p.getErrorPoints(shield, "1239.xyz");
    assertEquals(true, list.size() == 1);
  }

  @Test
  public void testAlphanumericAndMoreTypeSpecialChars()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMoreSpecialChars", "a b\tc\nd\re", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "AlphanumericAndMoreSpecialChars", "a \\", false, false));
  }

  @Test
  public void testAlphanumericAndMoreTypeCurlyBraces()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "AlphanumericAndMoreCurlyBraces", "{a}", false, false));
  }

  @Test
  public void testChar()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "Char", "a", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Char", "1", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Char", "-", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Char", " ", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Char", "12", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Char", "123456", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Char", "<asdffff.", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Char", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Char", null, false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "CharRequired", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "CharRequired", null, false, false));

    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "c", "error msg1", null, 1, 0);
    ItemChar p = new ItemChar(id);
    assertTrue(p.inError(req, shield, "12345", false, false));
    assertFalse(p.inError(req, shield, "1", false, false));
    assertFalse(p.inError(req, shield, "", false, false));
    assertFalse(p.inError(req, shield, null, false, false));
  }

  @Test
  public void testOpen()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "Open", "a", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Open", "1 ", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Open", "-a", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Open", "%$", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Open", ")9)_!@#$%^&*()_+=-`1234567890-=[]\\{>?>?<,./}|", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Open", "1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Open", "<asdffff.", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Open", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Open", null, false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "OpenRequired", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "OpenRequired", null, false, false));

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
    assertTrue(shield.threat(req, shield.parameters, "openErrorPoints", "123456", false, false));
    String s = Sanwaf.getErrors(req);
    assertTrue(s != null && s.contains("\"value\":\"123456\"") && s.contains("\"samplePoints\":"));

    req = new MockHttpServletRequest();
    assertTrue(shield.threat(req, shield.parameters, "openErrorPointsMask", "123456", false, false));
    s = Sanwaf.getErrors(req);
    assertTrue(s != null && s.contains("\"value\":\"***\""));
  }

  @Test
  public void testRegex()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "CustomRegexSSN", "555-55-5555", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "CustomRegexSSN", "abc-de-fghi", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "CustomRegexSSN", "5555555555", false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "CustomTel", "555-555-5555", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "CustomTel", "55-555-55556", false, false));

    assertEquals(true, shield.threat(req, shield.parameters, "CustomDate", "20160101", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "CustomDate", "2016-01-01", false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "lengthR_0_11", "555-55-5555", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "lengthR_0_11", "abc-de-fghi", false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "lengthR2_0_11", "555-55-5555", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "lengthR2_0_11", "abc-de-fghi", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "lengthR2_0_11", "555-55-55", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "lengthR2_0_11", "555-55-5555-55", false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "Regex", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Regex", null, false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "RegexRequired", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "RegexRequired", null, false, false));
  }

  @Test
  public void testRegexType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "r{telephone}", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemRegex p = new ItemRegex(id);
    assertTrue(p.patternName != null && p.patternName.length() > 0);

    assertEquals(false, p.inError(req, shield, "416-555-5555", false, false));
    assertEquals(true, p.inError(req, shield, "abc-def-ghij", false, false));
    assertEquals(true, p.inError(req, shield, "a", false, false));
    assertEquals(true, p.inError(req, shield, "abc-def-ghij-klmn", false, false));

    List<Point> list = p.getErrorPoints(shield, "");
    assertEquals(true, list.size() == 0);
    list = p.getErrorPoints(shield, null);
    assertEquals(true, list.size() == 0);
    list = p.getErrorPoints(shield, "416-555-5555");
    assertEquals(true, list.size() == 1);
    list = p.getErrorPoints(shield, "abc123def456");
    assertEquals(true, list.size() == 1);
  }

  @Test
  public void testRegexTypeInvalidFormta()
  {
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "r telephone", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemRegex p = new ItemRegex(id);
    assertTrue(p.patternName == null);
    assertTrue(p.rule == null);
  }

  @Test
  public void testConstantType()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "Constant", "FOO", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Constant", "BAR", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Constant", "FAR", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Constant", null, false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Constant", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "ConstantRequired", null, false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "ConstantRequired", "", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Constant", "foo", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Constant", "bar", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Constant", "far", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Constant", "FOOO", false, false));

    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "rk FOO,BAR", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemConstant p = new ItemConstant(id);
    assertTrue(p.constants == null);
    id = new ItemData(shield, "key1", Modes.BLOCK, "", "k FOO}", "error msg1", null, Integer.MAX_VALUE, 0);
    p = new ItemConstant(id);
    assertTrue(p.constants == null);

    id = new ItemData(shield, "key1", Modes.BLOCK, "", "", "error msg1", null, Integer.MAX_VALUE, 0);
    p = new ItemConstant(id);
    assertTrue(p.constants == null);
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
    assertEquals(true, shield.threat(req, shield.parameters, "Java", "12345", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "Java", "12345678901", false, false));// violates
    // max
    // setting
    assertEquals(false, shield.threat(req, shield.parameters, "Java", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "JavaRequired", null, false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "JavaRequired", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Java", "10", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Java", null, false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Java", "0001", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "Java", "0000", false, false));
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
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(false));

    request = new MockHttpServletRequest();
    request.addParameter("JavaMultiParm", "foobarfoobar");
    request.addParameter("JavaMultiParm2", "foobarfoobar");
    request.addParameter("JavaMultiParm3", "foobar");
    result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(true));

    request = new MockHttpServletRequest();
    request.addParameter("JavaMultiParm", "foobarfoobar");
    request.addParameter("JavaMultiParm2", "foobar");
    request.addParameter("JavaMultiParm3", "foobarfoobar");
    result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(true));

    request = new MockHttpServletRequest();
    request.addParameter("JavaMultiParm", "foobar");
    request.addParameter("JavaMultiParm2", "foobarfoobar");
    request.addParameter("JavaMultiParm3", "foobarfoobar");
    result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(true));
  }

  @Test
  public void testJavaInvalidClass()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    boolean b = shield.threat(req, shield.parameters, "JavaInvalidClass", "0000", false, false);
    assertEquals(true, b);

    req = new MockHttpServletRequest();
    b = shield.threat(req, shield.parameters, "JavaInvalidClass2", "0000", false, false);
    assertEquals(true, b);

    req = new MockHttpServletRequest();
    b = shield.threat(req, shield.parameters, "JavaInvalidClassEmpty", "0000", false, false);
    assertEquals(true, b);

    req = new MockHttpServletRequest();
    b = shield.threat(req, shield.parameters, "JavaInvalidClassNoPackage", "0000", false, false);
    assertEquals(true, b);
  }

  @Test
  public void testJavaInvalidMethod()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    boolean b = shield.threat(req, shield.parameters, "JavaInvalidMethod", "0000", false, false);
    assertEquals(false, b);
  }

  @Test
  public void testFormatType()
  {
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "f{(###) ###-####", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemFormat p = new ItemFormat(id);
    assertTrue(p.formatString != null);
    assertTrue(p.formatString.length() > 0);
  }

  @Test
  public void testInvalidFormatType()
  {
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "f {(###) ###-####", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemFormat p = new ItemFormat(id);
    assertTrue(p.formatString == null);
  }

  @Test
  public void testFormat()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat", "(123) 456-7890 abc ABC", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat", "BAR", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat", null, false, false));
  }

  @Test
  public void testFormatRequired()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatRequired", "(123) 456-7890 abc ABC", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired", "BAR", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatRequired", null, false, false));
  }

  @Test
  public void testFormat2Required()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0ZzZ", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Zzz", false, false));

    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", " Aac 0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "{Aac 0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "-Aac 0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "# ac 0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#{ac 0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#-ac 0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#A c 0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#A{c 0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#A-c 0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aa  0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aa{ 0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aa- 0Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac zZzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac {Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac -Zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0zzz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0{zz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0-zz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 00zz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Z0z", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0ZZz", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Z{z", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Z-z", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Zz ", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Zz0", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Zz{", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "#Aac 0Zz-", false, false));

    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "BAR", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatRequired2", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatRequired2", null, false, false));
  }

  @Test
  public void testFormat2()
  {
    // <item><name>parmformat2</name><type>f{#[1-12] / #[21-35]}</type>
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2", "12 / 30", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2", "01 / 30", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2", "12 / 21", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2", "12 / 35", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2", "11 / 29", false, false));

    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2", "a0 / 25", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2", "z0 / 25", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2", "/0 / 25", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2", ":0 / 25", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2", "00 / 25", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2", "13 / 25", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2", "93 / 25", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2", "01 / 20", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2", "01 / 36", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2", "01 / 99", false, false));

    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2", "0z / 9b", false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2", "", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2", null, false, false));
  }

  @Test
  public void testFormat2brackets()
  {
    // <item><name>parmformat2brackets</name><type>f{\[\]#[1-10]}</type>
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2brackets", "[]01", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2brackets", "[]02", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2brackets", "[]03", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2brackets", "[]04", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2brackets", "[]05", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2brackets", "[]06", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2brackets", "[]07", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2brackets", "[]08", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2brackets", "[]09", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat2brackets", "[]10", false, false));

    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2brackets", "[]00", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2brackets", "[]99", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2brackets", " ]01", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat2brackets", "[ 01", false, false));

    // <item><name>parmformat3</name><type>f{#[1-9]}</type>
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat3", "1", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat3", "2", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat3", "3", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat3", "4", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat3", "5", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat3", "6", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat3", "7", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat3", "8", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat3", "9", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat3", "10", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat3", "0", false, false));

    // <item><name>parmformat4</name><type>f{#[3,4,5,6]###-####-####-####}</type></item>
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat4", "3123-1234-1234-1234", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat4", "4123-1234-1234-1234", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat4", "5123-1234-1234-1234", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformat4", "6123-1234-1234-1234", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat4", "1123-1234-1234-1234", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat4", "2123-1234-1234-1234", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat4", "7123-1234-1234-1234", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat4", "8123-1234-1234-1234", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat4", "9123-1234-1234-1234", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformat4", "9123-1234-1234-12", false, false));

  }

  @Test
  public void testBadFormats()
  {
    // <item><name>parmformat2brackets</name><type>f{\[\]#[1-10]}</type>
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "parmbadformat1", "@", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmbadformat2", "@", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmbadformat3", "@", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmbadformat4", "@", false, false));
  }

  @Test
  public void testMultiFormats()
  {
    // <item><name>parmMultiFormat1</name><type>f{#####||#####-####}</type></item>
    // <item><name>parmMultiFormat2</name><type>f{#####||#####-####||A#A-#A#}</type></item>
    // <item><name>parmMultiFormat3</name><type>f{#####||#####-####||A#A-#A#||A##
    // A###}</type></item>
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "parmMultiFormat1", "12345", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmMultiFormat1", "12345-6789", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmMultiFormat1", "@", false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "parmMultiFormat2", "12345", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmMultiFormat2", "12345-6789", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmMultiFormat2", "A1B-2C3", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmMultiFormat2", "@", false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "parmMultiFormat3", "12345", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmMultiFormat3", "12345-6789", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmMultiFormat3", "A1B-2C3", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmMultiFormat3", "A12 B345", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmMultiFormat3", "A12 B5", false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "parmMultiFormatInvalid", "A12 B5", false, false));
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
    Boolean result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformat", "A1A-1A1");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(true));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "Canada");
    req.addParameter("depformat", "A1A-1A1");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "Canada");
    req.addParameter("depformat", "12345");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(true));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatMultiple", "12345-1234");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatMultiple", "A1A-1A1");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(true));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "xxxxx");
    req.addParameter("depformatMultiple", "A1A-1A1");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatMultiple", "1234");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(true));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatMultiple", "12345-123");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(true));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatRequired", "12345");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatRequired", "");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(true));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormatBadParent", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat1", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat2", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat3", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat4", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat5", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat6", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat7", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat8", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));

    req = new MockHttpServletRequest();
    req.addParameter("depformatParent", "US");
    req.addParameter("depformatInvalidFormat9", "aaaaa");
    result = sanwaf.isThreatDetected(req);
    assertTrue(result.equals(false));
  }

  @Test
  public void testDepFormatType()
  {
    ItemData id = new ItemData(shield, "key1", Modes.BLOCK, "", "d {depformatParent:US=#####;Canada=A#A-#A#", "error msg1", null, Integer.MAX_VALUE, 0);
    ItemDependentFormat p = new ItemDependentFormat(id);
    assertTrue(p.dependentElementName == null);
    assertTrue(p.depFormatString == null);
    assertTrue(p.formats.size() == 0);

    id = new ItemData(shield, "key1", Modes.BLOCK, "", "d{depformatParent:US=#####;Canada=A#A-#A#}", "error msg1", null, Integer.MAX_VALUE, 0);
    p = new ItemDependentFormat(id);
    assertTrue(p.dependentElementName.equals("depformatParent"));
    assertTrue(p.depFormatString.equals("depformatParent:US=#####;Canada=A#A-#A#"));
    assertTrue(p.formats.size() == 2);
  }

  @Test
  public void testFormatEscapceChars()
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
    assertEquals(false, shield.threat(req, shield.parameters, "parmformatEscapedChars", "#Aacx[]()|:=+-;1", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmMultiFormat3", "A12 B5", false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "parmformatEscapedXchar1", "!@#", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformatEscapedXchar2", "a9$ 9", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformatEscapedXchar3", "a9$ A", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformatEscapedXchar4", "a9$ a", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformatEscapedXchar5", "a9$ x", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformatEscapedXchar5", "a9$ X", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmformatEscapedXchar6", "a9$ 1", false, false));

    assertEquals(true, shield.threat(req, shield.parameters, "parmformatEscapedXchar1", "!@# ", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformatEscapedXchar2", "a9$ a", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformatEscapedXchar3", "a9$ a", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformatEscapedXchar4", "a9$ A", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformatEscapedXchar5", "a9$ 0", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformatEscapedXchar5", "a9$ 0", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmformatEscapedXchar6", "a9$ 0", false, false));
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
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDateOverflowMonth", "12", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDateOverflowDay", "31", false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDate1", String.valueOf(yy), false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDate1", String.valueOf(yy + 10), false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatWithDate1", String.valueOf(yy + 11), false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatWithDate1", String.valueOf(yy - 1), false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDate1a", String.valueOf(yy), false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDate1a", String.valueOf(yy - 10), false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatWithDate1a", String.valueOf(yy - 11), false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatWithDate1a", String.valueOf(yy + 1), false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDate2", String.valueOf(yyyy), false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDate2", String.valueOf(yyyy + 10), false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDate2a", String.valueOf(yyyy), false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDate2a", String.valueOf(yyyy - 10), false, false));

    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDate3", String.valueOf(dd), false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatWithDate4", String.valueOf(mm), false, false));
  }

  @Test
  public void testParmFormatIP()
  {
    // <item><name>parmFormatIP</name><type>f{#[0-255].#[0-255].#[0-255].#[0-255]}</type></item>
    MockHttpServletRequest req = new MockHttpServletRequest();
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatIP", "111.111.111.111", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatIP", "255.255.255.255", false, false));
    assertEquals(false, shield.threat(req, shield.parameters, "parmFormatIP", "000.000.000.000", false, false));

    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatIP", "1.1.1.1", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatIP", "1.1.1.1", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatIP", "1", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatIP", "1.1.1", false, false));
    assertEquals(true, shield.threat(req, shield.parameters, "parmFormatIP", "1", false, false));
  }

}

