package com.sanwaf.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class Metadata
{
  static final String XML_METADATA = "metadata";
  static final String XML_SECURED = "secured";
  static final String XML_PARAMETERS = "parameters";
  static final String XML_HEADERS = "headers";
  static final String XML_COOKIES = "cookies";
  static final String INDEX_PARM_MARKER = "  ";
  static final String STAR = "*";

  com.sanwaf.log.Logger logger;
  boolean enabled = false;
  boolean caseSensitive = true;
  boolean endpointIsStrict = false;
  boolean endpointIsStrictAllowLess = false;
  Modes endpointMode = Modes.BLOCK;
  Map<String, Item> items = new HashMap<>();
  Map<String, List<String>> index = new HashMap<>();
  Shield shield;

  Metadata(Shield shield, Xml xml, String type, com.sanwaf.log.Logger logger, boolean isDetect)
  {
    this.logger = logger;
    this.shield = shield;
    load(shield, xml, type, isDetect);
  }

  //used for endpoints
  Metadata(Shield shield, String itemsString, boolean caseSensitive, boolean includeEndpointAttributes, String endpointIsStrict, com.sanwaf.log.Logger logger, boolean isDetect)
  {
    this.logger = logger;
    loadEndpoints(shield, itemsString, caseSensitive, includeEndpointAttributes, isDetect);

    if ("true".equalsIgnoreCase(endpointIsStrict))
    {
      this.endpointIsStrict = true;
    }
    else if ("<".equals(endpointIsStrict) || "less".equalsIgnoreCase(endpointIsStrict))
    {
      this.endpointIsStrict = true;
      this.endpointIsStrictAllowLess = true;
    }
  }

  void load(Shield shield, Xml xml, String type, boolean isDetect)
  {
    initA2Zindex(index);

    String metadataBlock = xml.get(XML_METADATA);
    Xml metadataBlockXml = new Xml(metadataBlock);
    String securedBlock = metadataBlockXml.get(XML_SECURED);
    Xml securedBlockXml = new Xml(securedBlock);

    String enabledViewBlock = metadataBlockXml.get(Shield.XML_ENABLED);
    Xml enabledViewdBlockXml = new Xml(enabledViewBlock);
    enabled = Boolean.parseBoolean(enabledViewdBlockXml.get(type));

    String caseBlock = metadataBlockXml.get(Shield.XML_CASE_SENSITIVE);
    Xml caseBlockXml = new Xml(caseBlock);
    caseSensitive = Boolean.parseBoolean(caseBlockXml.get(type));

    String subBlock = securedBlockXml.get(type);
    Xml subBlockXml = new Xml(subBlock);
    String[] xmlItems = subBlockXml.getAll(ItemFactory.XML_ITEM);
    for (String itemString : xmlItems)
    {
      loadItem(shield, itemString, false, isDetect);
    }
  }

  private void loadItem(Shield shield, String itemString, boolean includeEnpointAttributes, boolean isDetect)
  {
    Xml xml = new Xml(itemString);
    Item item = ItemFactory.parseItem(shield, xml, includeEnpointAttributes, logger);
    //do we want to load this item for the provided isDetect parm
    if ((isDetect && item.mode != null && (item.mode == Modes.BLOCK || item.mode == Modes.DISABLED)) ||
        (!isDetect && (item.mode != null && (item.mode == Modes.DETECT || item.mode == Modes.DETECT_ALL))))
    {
      return;
    }
    String namesString = xml.get(ItemFactory.XML_ITEM_NAME);

    if (namesString.contains(Shield.SEPARATOR))
    {
      String[] names = namesString.split(Shield.SEPARATOR);
      Item thisItem = item;
      for (String name : names)
      {
        name = refineName(name, index);
        if (name == null)
        {
          continue;
        }
        if (!caseSensitive)
        {
          name = name.toLowerCase();
        }
        thisItem.name = name;
        thisItem.display = name;
        items.put(name, thisItem);
      }
    }
    else
    {
      item.name = refineName(item.name, index);
      if (item.name != null)
      {
        if (!caseSensitive)
        {
          item.name = item.name.toLowerCase();
        }
        items.put(item.name, item);
      }
    }
  }

  void loadEndpoints(Shield shield, String itemsString, boolean caseSensitive, boolean includeEndpointAttributes, boolean isDetect)
  {
    initA2Zindex(index);
    enabled = true;
    this.caseSensitive = caseSensitive;

    Xml itemsXml = new Xml(itemsString);
    String[] xmlItems = itemsXml.getAll(ItemFactory.XML_ITEM);
    for (String itemString : xmlItems)
    {
      loadItem(shield, itemString, includeEndpointAttributes, isDetect);
    }
  }

  static void initA2Zindex(Map<String, List<String>> map)
  {
    for (char ch = 'a'; ch <= 'z'; ++ch)
    {
      map.put(String.valueOf(ch), null);
    }
  }

  static String refineName(String name, Map<String, List<String>> map)
  {
    int last = 0;
    while (true)
    {
      int starPos = name.indexOf(STAR, last);
      if (starPos < 0)
      {
        return name;
      }
      if (starPos == 0)
      {
        return null;
      }
      String f = name.substring(starPos - 1, starPos);
      String markerChars;

      if (starPos == name.length() - 1)
      {
        markerChars = INDEX_PARM_MARKER + name.substring(0, name.length() - 1);
      }
      else
      {
        markerChars = f + name.charAt(starPos + 1);
        if (!isNotAlphanumeric(markerChars))
        {
          return null;
        }
      }
      String firstCharOfKey = name.substring(0, 1);
      List<String> chars = map.computeIfAbsent(firstCharOfKey, k -> new ArrayList<>());
      if (!chars.contains(markerChars))
      {
        chars.add(markerChars);
      }
      name = name.substring(0, starPos) + name.substring(starPos + 1);
    }
  }

  static String stripEosNumbers(final String s)
  {
    int i = s.length() - 1;
    while (i > 0)
    {
      char c = s.charAt(i);
      int v = c - '0';
      if (v >= 0 && v <= 9)
      {
        i--;
        continue;
      }
      return s.substring(0, i + 1);
    }
    return s;
  }

  static boolean isNotAlphanumeric(String s)
  {
    char[] chars = s.toCharArray();
    for (char c : chars)
    {
      if (!(c < 0x30 || (c >= 0x3a && c <= 0x40) || (c > 0x5a && c <= 0x60) || c > 0x7a))
      {
        return false;
      }
    }
    return true;
  }

  static String jsonEncode(String s)
  {
    if (s == null)
    {
      return "";
    }
    else
    {
      s = s.replace("\\", "\\\\");
      s = s.replace("\"", "\\\"");
      return s.replace("/", "\\/");
    }
  }

  String getFromIndex(String key)
  {
    if (key == null)
    {
      return "";
    }
    List<String> list = index.get(key.substring(0, 1));
    if (list == null)
    {
      return null;
    }

    for (String s : list)
    {
      int last = 0;
      while (true)
      {
        if (s.length() != 2)
        {
          return resolveStarAtEndOfWord(key, list);
        }
        int start = key.indexOf(s.charAt(0), last);
        if (start <= 0)
        {
          break;
        }
        int end = key.indexOf(s.charAt(1), start + 1);
        last = end + 1;
        key = key.substring(0, start + 1) + key.substring(end);
      }
    }
    return key;
  }

  private String resolveStarAtEndOfWord(String key, List<String> list)
  {
    String k2 = stripEosNumbers(key);
    if (list.contains(INDEX_PARM_MARKER + k2))
    {
      return k2;
    }
    return null;
  }
}

