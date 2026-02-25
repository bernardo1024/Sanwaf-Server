package com.sanwaf.core;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

final class Xml
{
  static final String CDATA_START = "<![CDATA[";
  static final String CDATA_END = "]]>";

  private final String rawXml;

  Xml(String rawXml)
  {
    this.rawXml = stripXmlComments(rawXml);
  }

  Xml(URL url) throws IOException
  {
    if (url != null)
    {
      rawXml = stripXmlComments(readFile(url.openStream()));
    }
    else
    {
      throw new IOException("url provided is null");
    }
  }

  static String readFile(InputStream is) throws IOException
  {
    StringBuilder sb = new StringBuilder();
    int read = 0;
    byte[] data = new byte[1024];
    while (true)
    {
      read = is.read(data);
      if (read < 0)
      {
        break;
      }
      sb.append(new String(data));
      data = new byte[1024];
    }
    is.close();
    return sb.toString();
  }

  static String stripXmlComments(String s)
  {
    if (s == null || s.isEmpty())
    {
      return "";
    }
    return s.replaceAll("<!--.*-->", "").replaceAll("<!--((?!<!--)[\\s\\S])*-->", "");
  }

  public String toString()
  {
    return rawXml;
  }

  String get(String key)
  {
    return get(rawXml, key);
  }

  String get(String xml, String key)
  {
    if (xml == null || xml.isEmpty())
    {
      return "";
    }
    String xmlUc = xml.toLowerCase();
    String keyUc = "<" + key.toLowerCase() + ">";
    int start = xmlUc.indexOf(keyUc);
    if (start < 0)
    {
      return "";
    }
    String endKeyUc = "</" + key.toLowerCase() + ">";
    int end = xmlUc.indexOf(endKeyUc, start);
    if (end < 0)
    {
      return "";
    }
    String value = xml.substring(start + keyUc.length(), end);
    int cdataStart = value.indexOf(CDATA_START);
    if (cdataStart == 0)
    {
      int cdataEnd = value.indexOf(CDATA_END, cdataStart);
      return value.substring(cdataStart + CDATA_START.length(), cdataEnd);
    }
    return value;
  }

  String[] getAll(String key)
  {
    return getAll(rawXml, key);
  }

  String[] getAll(String xml, String key)
  {
    return getAll(xml, "<" + key + ">", "</" + key + ">");
  }

  private String[] getAll(String xml, String key, String endKey)
  {
    List<String> hits = new ArrayList<>();
    int old = 0;
    String xmlLc = xml.toLowerCase();
    String keyLc = key.toLowerCase();
    String endKeyLc = endKey.toLowerCase();
    int start = 0;
    int end = 0;

    while ((start = xmlLc.indexOf(keyLc, old)) >= 0)
    {
      end = xmlLc.indexOf(endKeyLc, start);
      if (end > start + keyLc.length())
      {
        hits.add(xml.substring(start + key.length(), end));
        old = end + endKey.length();
      }
      else
      {
        break;
      }
    }
    return hits.toArray(new String[0]);
  }
}

