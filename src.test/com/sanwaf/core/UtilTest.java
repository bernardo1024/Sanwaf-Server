package com.sanwaf.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.Test;

import com.sanwaf.core.Shield;
import com.sanwaf.core.Sanwaf;

public class UtilTest {
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass() {
    try {
      sanwaf = new Sanwaf();
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    } catch (IOException ioe) {
      assertTrue(false);
    }
  }

  @Test
  public void appendParameterItemMapToSBTest() {
    StringBuilder sb = new StringBuilder();
    Map<String, Parameter> m = new HashMap<>();
    Shield.appendPItemMapToSB(m, sb, "label");
    assertEquals(true, sb.indexOf("(none found)") > 0);

    Shield.appendPItemMapToSB(null, sb, "label");
    assertEquals(true, sb.indexOf("(none found)") > 0);

    sb = new StringBuilder();
    m = null;
    Shield.appendPItemMapToSB(m, sb, "label");
    assertEquals(true, sb.indexOf("(none found)") > 0);
  }

  @Test
  public void splitTest() {
    List<String> list = Shield.split(null);
    assertEquals(true, list.isEmpty());

    list = Shield.split("");
    assertEquals(true, list.isEmpty());

    list = Shield.split("1:::2::::::3");
    assertEquals(3, list.size());
  }

  @Test
  public void jsonEncodeTest() {
    String s = Metadata.jsonEncode(null);
    assertEquals(true, s.equals(""));
  }

  @Test
  public void parseIntTest() {
    int i = Shield.parseInt("12345", -123);
    assertEquals(true, i == 12345);
    i = Shield.parseInt("123abc", -123);
    assertEquals(true, i == -123);
  }

  @Test
  public void isNotAlphanumericTest() {
    char c = 0x29;
    assertEquals(true, Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x7b;
    assertEquals(true, Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x3b;
    assertEquals(true, Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x3c;
    assertEquals(true, Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x5b;
    assertEquals(true, Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x5c;
    assertEquals(true, Metadata.isNotAlphanumeric(String.valueOf(c)));

    c = 0x31;
    assertEquals(false, Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x39;
    assertEquals(false, Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x41;
    assertEquals(false, Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x59;
    assertEquals(false, Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x61;
    assertEquals(false, Metadata.isNotAlphanumeric(String.valueOf(c)));
    c = 0x79;
    assertEquals(false, Metadata.isNotAlphanumeric(String.valueOf(c)));
  }

  @Test
  public void isCharAlphanumericTest() {
    char c = 0x29;
    assertEquals(true, ParameterAlphanumeric.isCharNotAlphanumeric(c));
    c = 0x7b;
    assertEquals(true, ParameterAlphanumeric.isCharNotAlphanumeric(c));
    c = 0x3b;
    assertEquals(true, ParameterAlphanumeric.isCharNotAlphanumeric(c));
    c = 0x3c;
    assertEquals(true, ParameterAlphanumeric.isCharNotAlphanumeric(c));
    c = 0x5b;
    assertEquals(true, ParameterAlphanumeric.isCharNotAlphanumeric(c));
    c = 0x5c;
    assertEquals(true, ParameterAlphanumeric.isCharNotAlphanumeric(c));

    c = 0x31;
    assertEquals(false, ParameterAlphanumeric.isCharNotAlphanumeric(c));
    c = 0x39;
    assertEquals(false, ParameterAlphanumeric.isCharNotAlphanumeric(c));
    c = 0x41;
    assertEquals(false, ParameterAlphanumeric.isCharNotAlphanumeric(c));
    c = 0x59;
    assertEquals(false, ParameterAlphanumeric.isCharNotAlphanumeric(c));
    c = 0x61;
    assertEquals(false, ParameterAlphanumeric.isCharNotAlphanumeric(c));
    c = 0x79;
    assertEquals(false, ParameterAlphanumeric.isCharNotAlphanumeric(c));
  }

  @Test
  public void stripEOSnumbersTest() {
    String s = Metadata.stripEosNumbers("s");
    assert (s.equals("s"));
    s = Metadata.stripEosNumbers("s");
    assert (s.equals("s"));
    s = Metadata.stripEosNumbers("abc123");
    assert (s.equals("abc"));
  }

  @Test
  public void parseMethodNameTest() {
    assert (ParameterJava.parseMethod("foo.method()").equals("method"));
    assert (ParameterJava.parseMethod("foomethod()").equals("foomethod()"));
  }

  @Test
  public void refineNameTest() {
    assert (Metadata.refineName("*foo.method()", shield.parameters.index) == null);
    assert (Metadata.refineName("foo*abc", shield.parameters.index) == null);
  }

  @Test
  public void stripXmlCommentsTest() {
    assert (Xml.stripXmlComments("").equals(""));
    assert (Xml.stripXmlComments(null).equals(""));
  }
}