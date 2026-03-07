package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Parses and holds XML metadata configuration for a specific request-data
 * category (parameters, headers, cookies, or endpoints). Each instance owns
 * an immutable map of {@link Item} definitions keyed by name, along with a
 * wildcard index that supports pattern-based name matching (e.g., names
 * containing {@code *}). Metadata also tracks per-endpoint strict-mode and
 * case-sensitivity settings.
 */
class Metadata {
  static final String XML_METADATA = "metadata";
  static final String XML_SECURED = "secured";
  static final String XML_ENDPOINTS = "endpoints";
  static final String XML_ENDPOINT = "endpoint";
  static final String XML_STRICT = "strict";
  static final String XML_PARAMETERS = "parameters";
  static final String XML_HEADERS = "headers";
  static final String XML_COOKIES = "cookies";
  static final String INDEX_PARAM_MARKER = "  ";
  static final String STAR = "*";

  private static final String[] CHAR_STRINGS = new String[128];

  static {
    for (int i = 0; i < 128; i++) {
      CHAR_STRINGS[i] = String.valueOf((char) i);
    }
  }

  /**
   * Returns a cached single-character string for ASCII characters, or creates
   * one for characters outside the ASCII range.
   *
   * @param c the character to convert
   * @return a single-character string
   */
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

  /**
   * Retrieves an {@link Item} by key, applying case-sensitivity rules.
   *
   * @param key the item key to look up
   * @return the matching item, or {@code null} if not found
   */
  Item getItem(String key) {
    return items.get(caseSensitive ? key : key.toLowerCase());
  }

  /**
   * Constructs Metadata for a non-endpoint category (parameters, headers, or
   * cookies) by parsing the corresponding XML block.
   *
   * @param shield the parent shield
   * @param xml    the shield-level XML block
   * @param type   the metadata type ({@link #XML_PARAMETERS},
   *               {@link #XML_HEADERS}, or {@link #XML_COOKIES})
   * @param logger logger for warnings and errors during parsing
   */
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

  /**
   * Constructs Metadata for an endpoint, with explicit strict-mode and
   * case-sensitivity settings.
   *
   * @param shield            the parent shield
   * @param itemsString       the XML string containing item definitions
   * @param caseSensitive     whether item names are case-sensitive
   * @param endpointIsStrict  strict-mode value: "true", "less"/"&lt;", or other
   *                          (disabled)
   * @param logger            logger for warnings and errors during parsing
   * @param endpointMode      the mode for this endpoint (BLOCK, DETECT, etc.)
   */
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

  /**
   * Parses the metadata XML block for a given type, extracting enabled,
   * case-sensitivity, and the secured sub-block.
   *
   * @param xml  the shield-level XML block
   * @param type the metadata type to parse
   * @return a {@link ParsedMetadataXml} holding the parsed values
   */
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

  /**
   * Loads all item definitions from parsed metadata XML into the items and
   * index maps.
   *
   * @param shield the parent shield
   * @param parsed the parsed metadata XML
   * @param items  mutable map to populate with named items
   * @param index  mutable map to populate with wildcard index entries
   */
  private void loadItems(Shield shield, ParsedMetadataXml parsed, Map<String, Item> items, Map<String, Set<String>> index) {
    String[] xmlItems = parsed.subBlockXml.getAll(ItemFactory.XML_ITEM);
    for (String itemString : xmlItems) {
      loadItem(shield, itemString, false, items, index);
    }
  }

  /**
   * Parses a single item XML string. If the name contains the separator
   * ({@value Shield#SEPARATOR}), multiple items sharing the same definition
   * are created.
   *
   * @param shield                    the parent shield
   * @param itemString                the raw XML string for the item
   * @param includeEndpointAttributes whether to parse endpoint-specific
   *                                  attributes
   * @param items                     mutable map to populate
   * @param index                     mutable wildcard index map to populate
   */
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

  /**
   * Loads item definitions for an endpoint from the given XML string.
   *
   * @param shield      the parent shield
   * @param itemsString the XML string containing endpoint items
   * @param items       mutable map to populate with named items
   * @param index       mutable map to populate with wildcard index entries
   */
  private void loadEndpointItems(Shield shield, String itemsString, Map<String, Item> items, Map<String, Set<String>> index) {
    Xml itemsXml = new Xml(itemsString);
    String[] xmlItems = itemsXml.getAll(ItemFactory.XML_ITEM);
    for (String itemString : xmlItems) {
      loadItem(shield, itemString, true, items, index);
    }
  }

  /**
   * Processes wildcard markers ({@code *}) in an item name. Trailing wildcards
   * produce index entries for suffix-based lookup; mid-name wildcards produce
   * two-character boundary markers. The wildcard characters are stripped from
   * the returned name.
   *
   * @param name the raw item name, possibly containing {@code *} wildcards
   * @param map  the wildcard index map to update
   * @return the refined name with wildcards removed, or {@code null} if the
   *         name is invalid (e.g., starts with {@code *})
   */
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
        markerChars = INDEX_PARAM_MARKER + name.substring(0, name.length() - 1);
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

  /**
   * Strips trailing numeric digits from the end of a string.
   *
   * @param s the input string
   * @return the string with trailing digits removed, or the original string
   *         if it has no trailing digits
   */
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

  /**
   * Tests whether every character in the string is non-alphanumeric.
   *
   * @param s the string to test
   * @return {@code true} if all characters are non-alphanumeric
   */
  static boolean isNotAlphanumeric(String s) {
    for (int i = 0; i < s.length(); i++) {
      if (!ItemAlphanumeric.isNotAlphanumeric(s.charAt(i))) {
        return false;
      }
    }
    return true;
  }

  /**
   * Determines whether the request violates this endpoint's strict-mode rules.
   * In strict mode, every configured item must be present in the request, and
   * no unknown parameters are allowed. The "allow less" variant permits
   * missing items but still rejects unknown ones.
   *
   * @param req the servlet request to check
   * @return {@code true} if a strict-mode violation is detected
   */
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

  /**
   * Loads all endpoint definitions from the parsed metadata XML and returns
   * an immutable map of URI to Metadata.
   *
   * @param shield        the parent shield (may be {@code null} during testing)
   * @param parsed        the parsed metadata XML for endpoints
   * @param caseSensitive whether item names are case-sensitive
   * @param logger        logger for warnings and errors
   * @return an unmodifiable map from URI strings to endpoint Metadata
   */
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

  /**
   * Holds the parsed result of a metadata XML block: the enabled flag,
   * case-sensitivity flag, and the XML sub-block containing item definitions.
   */
  static class ParsedMetadataXml {
    final boolean enabled;
    final boolean caseSensitive;
    final Xml subBlockXml;

    /**
     * Constructs a ParsedMetadataXml with the given settings.
     *
     * @param enabled       whether this metadata type is enabled
     * @param caseSensitive whether item names are case-sensitive
     * @param subBlockXml   the XML sub-block containing item definitions
     */
    ParsedMetadataXml(boolean enabled, boolean caseSensitive, Xml subBlockXml) {
      this.enabled = enabled;
      this.caseSensitive = caseSensitive;
      this.subBlockXml = subBlockXml;
    }
  }

  /**
   * Resolves a parameter name against the wildcard index. Wildcard entries
   * strip variable segments from the key to produce a canonical name that
   * can be looked up in the items map.
   *
   * @param key the parameter name to resolve
   * @return the canonical item name, or {@code null} if no wildcard matches
   */
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

  /**
   * Finds the first occurrence of a character in a char buffer, starting from
   * a given index.
   *
   * @param buf  the character buffer to search
   * @param len  the effective length of the buffer
   * @param c    the character to find
   * @param from the index to start searching from
   * @return the index of the character, or {@code -1} if not found
   */
  private static int indexOfChar(char[] buf, int len, char c, int from) {
    for (int i = from; i < len; i++) {
      if (buf[i] == c) {
        return i;
      }
    }
    return -1;
  }

  /**
   * Checks whether the key (with trailing digits stripped) matches a
   * trailing-wildcard entry in the index.
   *
   * @param key  the parameter name (possibly with trailing digits)
   * @param list the set of index markers for the key's first character
   * @return the key with trailing digits stripped if a match is found, or
   *         {@code null} if no trailing-wildcard entry matches
   */
  private String resolveStarAtEndOfWord(String key, Set<String> list) {
    String k2 = stripEosNumbers(key);
    int markerLen = INDEX_PARAM_MARKER.length();
    int expected = markerLen + k2.length();
    for (String s : list) {
      if (s.length() == expected && s.regionMatches(markerLen, k2, 0, k2.length())) {
        return k2;
      }
    }
    return null;
  }
}
