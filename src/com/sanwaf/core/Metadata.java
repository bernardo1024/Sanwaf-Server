package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

class Metadata {
  static final String XML_METADATA = "metadata";
  static final String XML_SECURED = "secured";
  static final String XML_ENDPOINTS = "endpoints";
  static final String XML_ENDPOINT = "endpoint";
  static final String XML_STRICT = "strict";
  static final String XML_PARAMETERS = "parameters";
  static final String XML_HEADERS = "headers";
  static final String XML_COOKIES = "cookies";
  static final String INDEX_PARM_MARKER = "  ";
  static final String STAR = "*";

  private static final String[] CHAR_STRINGS = new String[128];

  static {
    for (int i = 0; i < 128; i++) {
      CHAR_STRINGS[i] = String.valueOf((char) i);
    }
  }

  static String charString(char c) {
    return c < 128 ? CHAR_STRINGS[c] : String.valueOf(c);
  }

  final com.sanwaf.log.Logger logger;
  final boolean enabled;
  final boolean caseSensitive;
  final boolean endpointIsStrict;
  final boolean endpointIsStrictAllowLess;
  final Modes endpointMode;
  final Map<String, Item> items;
  final Map<String, Set<String>> index;

  Item getItem(String key) {
    return items.get(caseSensitive ? key : key.toLowerCase());
  }

  Metadata(Shield shield, Xml xml, String type, com.sanwaf.log.Logger logger) {
    this.logger = logger;
    ParsedMetadataXml parsed = parseMetadataXml(xml, type);
    this.enabled = parsed.enabled;
    this.caseSensitive = parsed.caseSensitive;
    this.endpointIsStrict = false;
    this.endpointIsStrictAllowLess = false;
    this.endpointMode = Modes.BLOCK;
    Map<String, Item> mutableItems = new HashMap<>();
    Map<String, Set<String>> mutableIndex = new HashMap<>(36); // 26 A-Z keys; (26/0.75)+1 avoids resize
    loadItems(shield, parsed, mutableItems, mutableIndex);
    this.items = Collections.unmodifiableMap(mutableItems);
    this.index = Collections.unmodifiableMap(mutableIndex);
  }

  // used for endpoints
  Metadata(Shield shield, String itemsString, boolean caseSensitive, String endpointIsStrict, com.sanwaf.log.Logger logger, Modes endpointMode) {
    this.logger = logger;
    this.enabled = true;
    this.caseSensitive = caseSensitive;
    this.endpointMode = endpointMode;
    if ("true".equalsIgnoreCase(endpointIsStrict)) {
      this.endpointIsStrict = true;
      this.endpointIsStrictAllowLess = false;
    } else if ("<".equals(endpointIsStrict) || "less".equalsIgnoreCase(endpointIsStrict)) {
      this.endpointIsStrict = true;
      this.endpointIsStrictAllowLess = true;
    } else {
      this.endpointIsStrict = false;
      this.endpointIsStrictAllowLess = false;
    }
    Map<String, Item> mutableItems = new HashMap<>();
    Map<String, Set<String>> mutableIndex = new HashMap<>(36); // 26 A-Z keys; (26/0.75)+1 avoids resize
    loadEndpointItems(shield, itemsString, mutableItems, mutableIndex);
    this.items = Collections.unmodifiableMap(mutableItems);
    this.index = Collections.unmodifiableMap(mutableIndex);
  }

  static ParsedMetadataXml parseMetadataXml(Xml xml, String type) {
    String metadataBlock = xml.get(XML_METADATA);
    Xml metadataBlockXml = new Xml(metadataBlock);
    String securedBlock = metadataBlockXml.get(XML_SECURED);
    Xml securedBlockXml = new Xml(securedBlock);

    boolean enabled = Boolean.parseBoolean(new Xml(metadataBlockXml.get(Shield.XML_ENABLED)).get(type));
    boolean caseSensitive = Boolean.parseBoolean(new Xml(metadataBlockXml.get(Shield.XML_CASE_SENSITIVE)).get(type));
    Xml subBlockXml = new Xml(securedBlockXml.get(type));

    return new ParsedMetadataXml(enabled, caseSensitive, subBlockXml);
  }

  private void loadItems(Shield shield, ParsedMetadataXml parsed, Map<String, Item> items, Map<String, Set<String>> index) {
    String[] xmlItems = parsed.subBlockXml.getAll(ItemFactory.XML_ITEM);
    for (String itemString : xmlItems) {
      loadItem(shield, itemString, false, items, index);
    }
  }

  private void loadItem(Shield shield, String itemString, boolean includeEndpointAttributes, Map<String, Item> items, Map<String, Set<String>> index) {
    Xml xml = new Xml(itemString);
    String namesString = xml.get(ItemFactory.XML_ITEM_NAME);

    if (namesString.contains(Shield.SEPARATOR)) {
      String[] names = namesString.split(Shield.SEPARATOR);
      for (String name : names) {
        name = refineName(name, index);
        if (name == null) {
          continue;
        }
        Item item = ItemFactory.parseItem(shield, xml, name, includeEndpointAttributes, logger);
        item.display = name;
        items.put(caseSensitive ? name : name.toLowerCase(), item);
      }
    } else {
      Item item = ItemFactory.parseItem(shield, xml, includeEndpointAttributes, logger);
      item.name = refineName(item.name, index);
      if (item.name != null) {
        items.put(caseSensitive ? item.name : item.name.toLowerCase(), item);
      }
    }
  }

  private void loadEndpointItems(Shield shield, String itemsString, Map<String, Item> items, Map<String, Set<String>> index) {
    Xml itemsXml = new Xml(itemsString);
    String[] xmlItems = itemsXml.getAll(ItemFactory.XML_ITEM);
    for (String itemString : xmlItems) {
      loadItem(shield, itemString, true, items, index);
    }
  }

  static String refineName(String name, Map<String, Set<String>> map) {
    int last = 0;
    while (true) {
      int starPos = name.indexOf(STAR, last);
      if (starPos < 0) {
        return name;
      }
      if (starPos == 0) {
        return null;
      }
      String f = charString(name.charAt(starPos - 1));
      String markerChars;

      if (starPos == name.length() - 1) {
        markerChars = INDEX_PARM_MARKER + name.substring(0, name.length() - 1);
      } else {
        markerChars = f + name.charAt(starPos + 1);
        if (!isNotAlphanumeric(markerChars)) {
          return null;
        }
      }
      String firstCharOfKey = charString(name.charAt(0));
      Set<String> chars = map.computeIfAbsent(firstCharOfKey, k -> new LinkedHashSet<>());
      chars.add(markerChars);
      name = name.substring(0, starPos) + name.substring(starPos + 1);
    }
  }

  static String stripEosNumbers(final String s) {
    int i = s.length() - 1;
    while (i > 0) {
      char c = s.charAt(i);
      int v = c - '0';
      if (v >= 0 && v <= 9) {
        i--;
        continue;
      }
      if (i + 1 == s.length())
        return s;
      return s.substring(0, i + 1);
    }
    return s;
  }

  static boolean isNotAlphanumeric(String s) {
    for (int i = 0; i < s.length(); i++) {
      if (!ItemAlphanumeric.isNotAlphanumeric(s.charAt(i))) {
        return false;
      }
    }
    return true;
  }

  boolean isStrictError(ServletRequest req) {
    if (!endpointIsStrict) {
      return false;
    }
    if (!endpointIsStrictAllowLess) {
      for (Item item : items.values()) {
        String s = req.getParameter(item.name);
        if (s == null) {
          return true;
        }
      }
    }
    Enumeration<?> names = req.getParameterNames();
    while (names.hasMoreElements()) {
      String k = (String) names.nextElement();
      if (getItem(k) == null) {
        return true;
      }
    }
    return false;
  }

  static Map<String, Metadata> loadEndpoints(Shield shield, ParsedMetadataXml parsed, boolean caseSensitive, com.sanwaf.log.Logger logger) {
    Map<String, Metadata> endpoints = new HashMap<>();
    String[] xmlEndpoints = parsed.subBlockXml.getAll(XML_ENDPOINT);
    for (String endpointString : xmlEndpoints) {
      Xml endpointXml = new Xml(endpointString);
      String[] uris = endpointXml.get(ItemFactory.XML_ITEM_URI).split(":::");
      String strict = endpointXml.get(XML_STRICT);

      int start = endpointString.indexOf("<items>");
      int end = endpointString.indexOf("</items>");
      Xml mx = new Xml(endpointString.substring(0, start) + endpointString.substring(end + "</items>".length()));
      Modes mode = Modes.getMode(mx.get(ItemFactory.XML_ITEM_MODE), (shield != null ? shield.mode : Modes.BLOCK));
      String items = endpointXml.get(ItemFactory.XML_ITEMS);

      Metadata metadata = new Metadata(shield, items, caseSensitive, strict, logger, mode);
      for (String uri : uris) {
        endpoints.put(uri, metadata);
      }
    }
    return Collections.unmodifiableMap(endpoints);
  }

  static class ParsedMetadataXml {
    final boolean enabled;
    final boolean caseSensitive;
    final Xml subBlockXml;

    ParsedMetadataXml(boolean enabled, boolean caseSensitive, Xml subBlockXml) {
      this.enabled = enabled;
      this.caseSensitive = caseSensitive;
      this.subBlockXml = subBlockXml;
    }
  }

  String getFromIndex(String key) {
    if (key == null) {
      return null;
    }
    Set<String> list = index.get(charString(key.charAt(0)));
    if (list == null) {
      return null;
    }

    char[] buf = null;
    int bufLen = 0;
    for (String s : list) {
      int last = 0;
      while (true) {
        if (s.length() != 2) {
          if (buf != null) {
            key = new String(buf, 0, bufLen);
          }
          return resolveStarAtEndOfWord(key, list);
        }
        char c0 = s.charAt(0);
        char c1 = s.charAt(1);
        int start;
        int end;
        if (buf == null) {
          start = key.indexOf(c0, last);
          if (start <= 0) {
            break;
          }
          end = key.indexOf(c1, start + 1);
        } else {
          start = indexOfChar(buf, bufLen, c0, last);
          if (start <= 0) {
            break;
          }
          end = indexOfChar(buf, bufLen, c1, start + 1);
        }
        if (buf == null) {
          buf = key.toCharArray();
          bufLen = buf.length;
        }
        int removeCount = end - start - 1;
        System.arraycopy(buf, end, buf, start + 1, bufLen - end);
        bufLen -= removeCount;
        last = end + 1;
      }
    }
    if (buf != null) {
      return new String(buf, 0, bufLen);
    }
    return key;
  }

  private static int indexOfChar(char[] buf, int len, char c, int from) {
    for (int i = from; i < len; i++) {
      if (buf[i] == c) {
        return i;
      }
    }
    return -1;
  }

  private String resolveStarAtEndOfWord(String key, Set<String> list) {
    String k2 = stripEosNumbers(key);
    int markerLen = INDEX_PARM_MARKER.length();
    int expected = markerLen + k2.length();
    for (String s : list) {
      if (s.length() == expected && s.regionMatches(markerLen, k2, 0, k2.length())) {
        return k2;
      }
    }
    return null;
  }
}
