package com.sanwaf.core;

import com.sanwaf.log.SimpleLogger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class OtherClassesTest
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
  public void TestDefaultContructorParameterItem()
  {
    Sanwaf.SanwafConfig cfg = sanwaf.config;
    sanwaf.config = cfg.toBuilder().verbose(true).build();
    Item pi = new ItemString();
    String s = pi.toString();
    assertTrue(s.contains("\"type\":\"STRING\""));
  }

  @Test
  public void testWithVerboseFalse()
  {
    Sanwaf.SanwafConfig cfg = sanwaf.config;
    sanwaf.config = cfg.toBuilder().verbose(false).build();
    assertFalse(sanwaf.config.verbose);
    sanwaf.config = cfg;
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
    assertEquals("", Metadata.jsonEncode(null));

    // named escapes
    assertEquals("\\\\", Metadata.jsonEncode("\\"));
    assertEquals("\\\"", Metadata.jsonEncode("\""));
    assertEquals("\\/",  Metadata.jsonEncode("/"));
    assertEquals("\\n", Metadata.jsonEncode("\n"));
    assertEquals("\\r", Metadata.jsonEncode("\r"));
    assertEquals("\\t", Metadata.jsonEncode("\t"));
    assertEquals("\\b", Metadata.jsonEncode("\b"));
    assertEquals("\\f", Metadata.jsonEncode("\f"));

    // control chars via unicode escape
    assertEquals("\\" + "u0000", Metadata.jsonEncode("\u0000"));
    assertEquals("\\" + "u001f", Metadata.jsonEncode("\u001f"));

    // Unicode line/paragraph separators
    assertEquals("\\" + "u2028", Metadata.jsonEncode("\u2028"));
    assertEquals("\\" + "u2029", Metadata.jsonEncode("\u2029"));

    // clean string passthrough (no allocation)
    String clean = "hello world 123";
    assertTrue(clean == Metadata.jsonEncode(clean));

    // mixed content
    assertEquals("a\\nb\\\\c", Metadata.jsonEncode("a\nb\\c"));
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

