package com.sanwaf.core;

import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.MethodOrderer;

import java.io.IOException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestMethodOrder(MethodOrderer.MethodName.class)
public class XmlTest {
  @Test
  void TestXmlInit() {
    assertThrows(IOException.class, () -> new Xml((URL) null));
  }

  @Test
  void TestXmlNullUrl() {
    // noinspection SpellCheckingInspection
    assertThrows(IOException.class, () -> new Xml(new URL("lakdfsj")));
  }

  @Test
  public void TestXmlToString() throws IOException {
    Xml xml = new Xml(Sanwaf.class.getResource("/sanwaf.xml"));
    assertTrue(xml.toString().contains("<sanwaf>"));
  }

  @Test
  public void testXmlPassingNull() {
    assertEquals("", new Xml("").get(null, "test"));
  }

  @Test
  public void testXmlInvalidEndTag() {
    String data = "<sanwaf><foo>foo<foo></sanwaf>";
    Xml xml = new Xml(data);

    assertEquals("", xml.get(data, "foo"));
    assertEquals(data, xml.toString());
    assertEquals("", xml.get("<sanwaf></foo>foo<foo></sanwaf>", "foo"));
    assertEquals(0, new Xml("<sanwaf></foo>foo<foo></sanwaf>").getAll("foo").length);
  }
}
