package com.sanwaf.core;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.io.IOException;
import java.net.URL;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class XmlTest
{
  @Test
  public void TestXmlInit()
  {
    boolean error;
    try
    {
      URL url = null;
      new Xml(url);
      error = false;
    }
    catch (IOException ioe)
    {
      error = true;
    }
    assertTrue(error);
  }

  @Test
  public void TestXmlNullUrl()
  {
    boolean error;
    try
    {
      URL url = new URL("lakdfsj");
      new Xml(url);
      error = false;
    }
    catch (IOException ioe)
    {
      error = true;
    }
    assertTrue(error);
  }

  @Test
  public void TestXmlToString()
  {
    Xml xml;
    try
    {
      xml = new Xml(Sanwaf.class.getResource("/sanwaf.xml"));
    }
    catch (IOException e)
    {
      fail("SanWaf Failed to load properties file");
      return;
    }
    assertTrue(!xml.toString().isEmpty() && xml.toString().contains("<sanwaf>"));
  }

  @Test
  public void testXmlPassingNull()
  {
    Xml xml = new Xml("");
    String s = xml.get(null, "test");
    assertEquals("", s);
  }

  @Test
  public void testXmlInvalidEndTag()
  {
    Xml xml = new Xml("<sanwaf><foo>foo<foo></sanwaf>");
    String s = xml.get("<sanwaf><foo>foo<foo></sanwaf>", "foo");
    assertEquals("", s);

    assertEquals("<sanwaf><foo>foo<foo></sanwaf>", xml.toString());

    s = xml.get("<sanwaf></foo>foo<foo></sanwaf>", "foo");
    assertEquals("", s);

    String[] sa = xml.getAll("<sanwaf></foo>foo<foo></sanwaf>", "foo");
    assertEquals(0, sa.length);
  }
}

