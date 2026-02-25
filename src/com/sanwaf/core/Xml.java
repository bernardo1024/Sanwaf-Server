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
  private final String rawXmlLower;

  Xml(String rawXml)
  {
    this.rawXml = stripXmlComments(rawXml);
    this.rawXmlLower = this.rawXml.toLowerCase();
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
    rawXmlLower = rawXml.toLowerCase();
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
    StringBuilder sb = new StringBuilder(s.length());
    int pos = 0;
    while (pos < s.length())
    {
      int commentStart = s.indexOf("<!--", pos);
      if (commentStart < 0)
      {
        sb.append(s, pos, s.length());
        break;
      }
      sb.append(s, pos, commentStart);
      int commentEnd = s.indexOf("-->", commentStart + 4);
      if (commentEnd < 0)
      {
        sb.append(s, commentStart, s.length());
        break;
      }
      pos = commentEnd + 3;
    }
    return sb.toString();
  }

  public String toString()
  {
    return rawXml;
  }

  String get(String key)
  {
    return get(rawXml, rawXmlLower, key);
  }

  String get(String xml, String key)
  {
    if (xml == null || xml.isEmpty())
    {
      return "";
    }
    return get(xml, xml.toLowerCase(), key);
  }

  private String get(String xml, String xmlLc, String key)
  {
    if (xml == null || xml.isEmpty())
    {
      return "";
    }
    String keyLc = "<" + key.toLowerCase() + ">";
    int start = xmlLc.indexOf(keyLc);
    if (start < 0)
    {
      return "";
    }
    String endKeyLc = "</" + key.toLowerCase() + ">";
    int end = xmlLc.indexOf(endKeyLc, start);
    if (end < 0)
    {
      return "";
    }
    String value = xml.substring(start + keyLc.length(), end);
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
    return getAll(rawXml, rawXmlLower, "<" + key + ">", "</" + key + ">");
  }

  String[] getAll(String xml, String key)
  {
    if (xml == null || xml.isEmpty())
    {
      return new String[0];
    }
    return getAll(xml, xml.toLowerCase(), "<" + key + ">", "</" + key + ">");
  }

  private String[] getAll(String xml, String xmlLc, String key, String endKey)
  {
    List<String> hits = new ArrayList<>();
    int old = 0;
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

