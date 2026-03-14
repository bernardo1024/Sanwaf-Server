package com.sanwaf.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight XML parser that extracts element values by tag name.
 *
 * <p>This is not a general-purpose XML parser; it performs simple string-based
 * lookups (case-insensitive) and handles {@code CDATA} sections. XML comments
 * are stripped on construction so they never interfere with value extraction.
 */
final class Xml {
  /** Opening delimiter for an XML CDATA section. */
  static final String CDATA_START = "<![CDATA[";
  /** Closing delimiter for an XML CDATA section. */
  static final String CDATA_END = "]]>";

  private final String rawXml;
  private final String rawXmlLower;

  /**
   * Constructs an {@code Xml} instance from a raw XML string.
   *
   * <p>XML comments are stripped during construction.
   *
   * @param rawXml the raw XML content
   */
  Xml(String rawXml) {
    this.rawXml = stripXmlComments(rawXml);
    this.rawXmlLower = this.rawXml.toLowerCase();
  }

  /**
   * Constructs an {@code Xml} instance by reading the content from a URL.
   *
   * @param url the URL to read XML content from
   * @throws IOException if the URL is {@code null} or the stream cannot be read
   */
  Xml(URL url) throws IOException {
    if (url != null) {
      rawXml = stripXmlComments(readFile(url.openStream()));
    } else {
      throw new IOException("url provided is null");
    }
    rawXmlLower = rawXml.toLowerCase();
  }

  /**
   * Reads the entire content of an {@link InputStream} into a string using UTF-8.
   *
   * @param is the input stream to read
   * @return the full content as a string
   * @throws IOException if an I/O error occurs while reading
   */
  static String readFile(InputStream is) throws IOException {
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8), 4096)) {
      StringBuilder sb = new StringBuilder();
      char[] buf = new char[4096];
      int read;
      while ((read = reader.read(buf)) != -1) {
        sb.append(buf, 0, read);
      }
      return sb.toString();
    }
  }

  /**
   * Strips all XML comments ({@code <!-- ... -->}) from the given string.
   *
   * @param s the XML string to process; may be {@code null}
   * @return the string with all comments removed, or an empty string if
   *         {@code s} is {@code null} or empty
   */
  static String stripXmlComments(String s) {
    if (s == null || s.isEmpty()) {
      return "";
    }
    StringBuilder sb = new StringBuilder(s.length());
    int pos = 0;
    while (pos < s.length()) {
      int commentStart = s.indexOf("<!--", pos);
      if (commentStart < 0) {
        sb.append(s, pos, s.length());
        break;
      }
      sb.append(s, pos, commentStart);
      int commentEnd = s.indexOf("-->", commentStart + 4);
      if (commentEnd < 0) {
        sb.append(s, commentStart, s.length());
        break;
      }
      pos = commentEnd + 3;
    }
    return sb.toString();
  }

  /**
   * Returns the raw XML content (with comments stripped).
   *
   * @return the XML string
   */
  public String toString() {
    return rawXml;
  }

  /**
   * Extracts the text content of the first element matching {@code key}
   * from the stored XML.
   *
   * @param key the element tag name (without angle brackets)
   * @return the element's text content, or an empty string if not found
   */
  String get(String key) {
    return get(rawXml, rawXmlLower, key);
  }

  /**
   * Extracts the text content of the first element matching {@code key}
   * from the provided XML fragment.
   *
   * @param xml the XML fragment to search
   * @param key the element tag name (without angle brackets)
   * @return the element's text content, or an empty string if not found
   */
  String get(String xml, String key) {
    if (xml == null || xml.isEmpty()) {
      return "";
    }
    return get(xml, xml.toLowerCase(), key);
  }

  /**
   * Core extraction logic. Performs a case-insensitive search for
   * {@code <key>...</key>} in the XML and returns the inner text,
   * unwrapping CDATA if present.
   *
   * @param xml   the original-case XML string
   * @param xmlLc the lower-cased XML string used for searching
   * @param key   the element tag name (without angle brackets)
   * @return the element's text content, or an empty string if not found
   */
  private String get(String xml, String xmlLc, String key) {
    if (xml == null || xml.isEmpty()) {
      return "";
    }
    String keyLc = "<" + key.toLowerCase() + ">";
    int start = xmlLc.indexOf(keyLc);
    if (start < 0) {
      return "";
    }
    String endKeyLc = "</" + key.toLowerCase() + ">";
    int end = xmlLc.indexOf(endKeyLc, start);
    if (end < 0) {
      return "";
    }
    String value = xml.substring(start + keyLc.length(), end);
    int cdataStart = value.indexOf(CDATA_START);
    if (cdataStart == 0) {
      int cdataEnd = value.indexOf(CDATA_END, cdataStart);
      return value.substring(cdataStart + CDATA_START.length(), cdataEnd);
    }
    return value;
  }

  /**
   * Returns the text content of every element matching {@code key} in the
   * stored XML.
   *
   * @param key the element tag name (without angle brackets)
   * @return an array of matched element contents; empty array if none found
   */
  String[] getAll(String key) {
    return getAll(rawXml, rawXmlLower, "<" + key + ">", "</" + key + ">");
  }

  /**
   * Finds all occurrences of elements delimited by {@code key} and
   * {@code endKey} and returns their inner text.
   *
   * @param xml      the original-case XML string
   * @param xmlLc    the lower-cased XML string used for searching
   * @param key      the opening tag (e.g. {@code <item>})
   * @param endKey   the closing tag (e.g. {@code </item>})
   * @return an array of matched element contents; empty array if none found
   */
  private String[] getAll(String xml, String xmlLc, String key, String endKey) {
    List<String> hits = new ArrayList<>();
    int keyLen = key.length();
    int endKeyLen = endKey.length();
    int pos = 0;
    int start;
    int end;

    while ((start = xmlLc.indexOf(key, pos)) >= 0) {
      end = xmlLc.indexOf(endKey, start + keyLen);
      if (end < 0) {
        break;
      }
      hits.add(xml.substring(start + keyLen, end));
      pos = end + endKeyLen;
    }
    return hits.toArray(new String[0]);
  }
}
