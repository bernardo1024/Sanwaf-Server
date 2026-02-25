package com.sanwaf.core;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.net.URL;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class XmlTest
{
  @Test(expected = IOException.class)
  public void TestXmlInit() throws IOException
  {
    new Xml((URL) null);
  }

  @Test(expected = IOException.class)
  public void TestXmlNullUrl() throws IOException
  {
    //noinspection SpellCheckingInspection
    new Xml(new URL("lakdfsj"));
  }

  @Test
  public void TestXmlToString() throws IOException
  {
    Xml xml = new Xml(Sanwaf.class.getResource("/sanwaf.xml"));
    assertTrue(xml.toString().contains("<sanwaf>"));
  }

  @Test
  public void testXmlPassingNull()
  {
    assertEquals("", new Xml("").get(null, "test"));
  }

  @Test
  public void testXmlInvalidEndTag()
  {
    String data = "<sanwaf><foo>foo<foo></sanwaf>";
    Xml xml = new Xml(data);

    assertEquals("", xml.get(data, "foo"));
    assertEquals(data, xml.toString());
    assertEquals("", xml.get("<sanwaf></foo>foo<foo></sanwaf>", "foo"));
    assertEquals(0, xml.getAll("<sanwaf></foo>foo<foo></sanwaf>", "foo").length);
  }
}

