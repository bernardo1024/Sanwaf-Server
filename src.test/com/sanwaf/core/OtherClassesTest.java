package com.sanwaf.core;

import com.sanwaf.log.SimpleLogger;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class OtherClassesTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
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
  public void TestDefaultContructorParameterItem()
  {
    Sanwaf.SanwafConfig cfg = sanwaf.config;
    sanwaf.config = cfg.withVerbose(true);
    Item pi = new ItemString();
    String s = pi.toString();
    assertTrue(s.contains("\"type\":\"STRING\""));
  }

  @Test
  public void TestLoggerSystemOut()
  {
    SimpleLogger logger = new SimpleLogger();
    logger.error("foobar-error");
    logger.info("foobar-info");

    assertTrue(true);
  }

  @Test
  public void splitTest()
  {
    List<String> list = Shield.split(null);
    assertTrue(list.isEmpty());

    list = Shield.split("");
    assertTrue(list.isEmpty());

    list = Shield.split("1:::2::::::3");
    assertEquals(3, list.size());
  }

  @Test
  public void jsonEncodeTest()
  {
    String s = Metadata.jsonEncode(null);
    assertEquals("", s);
  }

  @Test
  public void parseIntTest()
  {
    int i = Shield.parseInt("12345", -123);
    assertEquals(12345, i);
    i = Shield.parseInt("123abc", -123);
    assertEquals(-123, i);
  }

  @Test
  public void isNotAlphanumericTest()
  {
    char c = 0x29;
    assertTrue(Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x7b;
    assertTrue(Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x3b;
    assertTrue(Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x3c;
    assertTrue(Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x5b;
    assertTrue(Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x5c;
    assertTrue(Metadata.isNotAlphanumeric(String.valueOf(c)));

    c = 0x31;
    assertFalse(Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x39;
    assertFalse(Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x41;
    assertFalse(Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x59;
    assertFalse(Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x61;
    assertFalse(Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x79;
    assertFalse(Metadata.isNotAlphanumeric(String.valueOf(c)));
  }

  @Test
  public void isCharAlphanumericTest()
  {
    char c = 0x29;
    assertTrue(ItemAlphanumeric.isNotAlphanumeric(c));
    c = 0x7b;
    assertTrue(ItemAlphanumeric.isNotAlphanumeric(c));
    c = 0x3b;
    assertTrue(ItemAlphanumeric.isNotAlphanumeric(c));
    c = 0x3c;
    assertTrue(ItemAlphanumeric.isNotAlphanumeric(c));
    c = 0x5b;
    assertTrue(ItemAlphanumeric.isNotAlphanumeric(c));
    c = 0x5c;
    assertTrue(ItemAlphanumeric.isNotAlphanumeric(c));

    c = 0x31;
    assertFalse(ItemAlphanumeric.isNotAlphanumeric(c));
    c = 0x39;
    assertFalse(ItemAlphanumeric.isNotAlphanumeric(c));
    c = 0x41;
    assertFalse(ItemAlphanumeric.isNotAlphanumeric(c));
    c = 0x59;
    assertFalse(ItemAlphanumeric.isNotAlphanumeric(c));
    c = 0x61;
    assertFalse(ItemAlphanumeric.isNotAlphanumeric(c));
    c = 0x79;
    assertFalse(ItemAlphanumeric.isNotAlphanumeric(c));
  }

  @Test
  public void stripEOSnumbersTest()
  {
    String s = Metadata.stripEosNumbers("s");
    assert (s.equals("s"));
    s = Metadata.stripEosNumbers("s");
    assert (s.equals("s"));
    s = Metadata.stripEosNumbers("abc123");
    assert (s.equals("abc"));
  }

  @Test
  public void refineNameTest()
  {
    assert (Metadata.refineName("*foo.method()", shield.parameters.index) == null);
    assert (Metadata.refineName("foo*abc", shield.parameters.index) == null);
  }

  @Test
  public void stripXmlCommentsTest()
  {
    assert (Xml.stripXmlComments("").isEmpty());
    assert (Xml.stripXmlComments(null).isEmpty());
  }
}

