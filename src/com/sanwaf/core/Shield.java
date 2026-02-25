package com.sanwaf.core;

import com.sanwaf.core.Sanwaf.AllowListType;
import com.sanwaf.log.Logger;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

final class Shield
{
  private static final String STRICT_PARAMETER_DETECTED = "URI Strict Parameter Error - Unknown Parameter Detected";
  private static final String FAIL_ON_MATCH = "\tfailOnMatch=";
  private static final String REGEX_FILE_MARKER = "file=";
  Sanwaf sanwaf = null;
  Logger logger = null;
  String name = null;
  Modes mode = Modes.BLOCK;
  Shield childShield = null;
  int minLen = 0;
  int maxLen = Integer.MAX_VALUE;
  int regexMinLen = 0;
  boolean regexAlways = false;
  Map<String, String> errorMessages = new HashMap<>();
  List<String> regexAlwaysExclusions = new ArrayList<>();
  Map<String, Rule> rulePatterns = new HashMap<>();
  Map<String, Rule> customRulePatterns = new HashMap<>();
  Map<String, Rule> rulePatternsDetect = new HashMap<>();
  Map<String, Rule> customRulePatternsDetect = new HashMap<>();
  Metadata parameters = null;
  Metadata cookies = null;
  Metadata headers = null;
  Metadata parametersDetect = null;
  Metadata cookiesDetect = null;
  Metadata headersDetect = null;
  MetadataEndpoints endpoints = null;
  MetadataEndpoints endpointsDetect = null;

  Shield(Sanwaf sanwaf, Xml xml, Xml shieldXml, Logger logger)
  {
    this.sanwaf = sanwaf;
    this.logger = logger;
    load(sanwaf, xml, shieldXml, logger);
    logStartup();
  }

  boolean threatDetected(ServletRequest req, boolean doAllBlocks, boolean log)
  {
    return ((endpoints.enabled && endpointsThreatDetected(req, doAllBlocks, log)) ||
        (parameters.enabled && parameterThreatDetected(req, doAllBlocks, log)) ||
        (headers.enabled && headerThreatDetected(req, doAllBlocks, log)) ||
        (cookies.enabled && cookieThreatDetected(req, doAllBlocks, log)));
  }

  private boolean endpointsThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log)
  {
    HttpServletRequest hreq = (HttpServletRequest) req;
    String uri = hreq.getRequestURI();
    Enumeration<?> names = null;
    String k = null;
    String[] values = null;
    boolean threat = false;

    if (doAllBlocks)
    {
      Metadata metadataDetectDetect = endpointsDetect.endpointParametersDetect.get(uri);
      Metadata metadataDetectBlock = endpointsDetect.endpointParametersBlock.get(uri);
      names = req.getParameterNames();
      if (metadataDetectDetect != null)
      {
        while (names.hasMoreElements())
        {
          k = (String) names.nextElement();
          values = req.getParameterValues(k);
          for (String v : values)
          {
            if (metadataDetectDetect.endpointMode == Modes.DISABLED)
            {
              continue;
            }
            threat(req, metadataDetectDetect, k, v, true, true, log);
            threat(req, metadataDetectBlock, k, v, true, true, log);
          }
        }
      }
    }

    names = req.getParameterNames();
    Metadata metadataBlockDetect = endpoints.endpointParametersDetect.get(uri);
    Metadata metadataBlockBlock = endpoints.endpointParametersBlock.get(uri);
    if (metadataBlockDetect != null)
    {
      while (names.hasMoreElements())
      {
        k = (String) names.nextElement();
        values = req.getParameterValues(k);
        if (!doAllBlocks && metadataBlockDetect.endpointMode != Modes.DISABLED)
        {
          for (String v : values)
          {
            threat(req, metadataBlockDetect, k, v, true, false, log);
          }
        }
        for (String v : values)
        {
          if (metadataBlockBlock != null && metadataBlockBlock.endpointMode != Modes.DISABLED &&
              threat(req, metadataBlockBlock, k, v, true, doAllBlocks, log))
          {
            if (!doAllBlocks)
            {
              return true;
            }
            threat = true;
          }
        }
      }
    }
    return threat;
  }

  private boolean parameterThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log)
  {
    boolean retstring = false;
    String k = null;
    String[] values = null;
    Enumeration<?> names = req.getParameterNames();
    while (names.hasMoreElements())
    {
      k = (String) names.nextElement();
      values = req.getParameterValues(k);
      //log all detects first
      for (String v : values)
      {
        threat(req, parametersDetect, k, v, false, doAllBlocks, log);
      }
      //do blocks
      for (String v : values)
      {
        if (threat(req, parameters, k, v, false, doAllBlocks, log))
        {
          if (!doAllBlocks)
          {
            return true;
          }
          retstring = true;
        }
      }
    }
    return retstring;
  }

  private boolean headerThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log)
  {
    boolean threat = false;
    Enumeration<?> names = ((HttpServletRequest) req).getHeaderNames();
    while (names.hasMoreElements())
    {
      String s = String.valueOf(names.nextElement());
      Enumeration<?> headerEnumeration = ((HttpServletRequest) req).getHeaders(s);
      while (headerEnumeration.hasMoreElements())
      {
        threat(req, headersDetect, s, (String) headerEnumeration.nextElement(), false, doAllBlocks, log);
      }
    }

    names = ((HttpServletRequest) req).getHeaderNames();
    while (names.hasMoreElements())
    {
      String s = String.valueOf(names.nextElement());
      Enumeration<?> headerEnumeration = ((HttpServletRequest) req).getHeaders(s);
      while (headerEnumeration.hasMoreElements())
      {
        if (threat(req, headers, s, (String) headerEnumeration.nextElement(), false, doAllBlocks, log))
        {
          if (!doAllBlocks)
          {
            return true;
          }
          threat = true;
        }
      }
    }
    return threat;
  }

  private boolean cookieThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log)
  {
    boolean threat = false;
    Cookie[] cookieArray = ((HttpServletRequest) req).getCookies();
    if (cookieArray == null)
    {
      return false;
    }
    for (Cookie c : cookieArray)
    {
      threat(req, cookiesDetect, c.getName(), c.getValue(), false, doAllBlocks, log);
    }

    for (Cookie c : cookieArray)
    {
      if (threat(req, cookies, c.getName(), c.getValue(), false, doAllBlocks, log))
      {
        if (!doAllBlocks)
        {
          return true;
        }
        threat = true;
      }
    }
    return threat;
  }

  boolean threat(String v, boolean log)
  {
    return threat(null, null, "", v, false, false, false, log);
  }

  boolean threat(ServletRequest req, Metadata meta, String key, String value, boolean isEndpoint, boolean log)
  {
    return threat(req, meta, key, value, isEndpoint, false, false, log);
  }

  boolean threat(ServletRequest req, Metadata meta, String key, String value, boolean isEndpoint, boolean doAllBlocks, boolean log)
  {
    return threat(req, meta, key, value, isEndpoint, false, doAllBlocks, log);
  }

  boolean threat(ServletRequest req, Metadata meta, String key, String value, boolean isEndpoint, boolean forceStringPatterns, boolean doAllBlocks, boolean log)
  {
    if (value == null)
    {
      return false;
    }
    int len = value.length();
    if (len < minLen || len > maxLen)
    {
      return handleChildShield(req, value, log);
    }
    Item item;
    if (meta != null)
    {
      item = getItemFromMetaOrIndex(meta, key);
      if (item == null)
      {
        if (forceStringPatterns)
        {
          item = new ItemString();
        }
        else
        {
          if (meta.endpointIsStrict && MetadataEndpoints.isStrictError(req, meta))
          {
            Item.handleStrictError(STRICT_PARAMETER_DETECTED, req, logger, log);
            return true;
          }
          return false;
        }
      }
    }
    else
    {
      item = new ItemString();
    }

    if (item.required && value.isEmpty())
    {
      item.handleMode(true, value, req, item.mode, log, doAllBlocks);
      //return item.returnBasedOnDoAllBlocks(true, doAllBlocks);
      return true;
    }

    String relmsg = item.isRelateValid(value, req, meta);
    if (relmsg != null)
    {
      item.relatedErrMsg = relmsg;
      item.handleMode(true, value, req, item.mode, log, doAllBlocks);
      //return item.returnBasedOnDoAllBlocks(true, doAllBlocks);
      return true;
    }

    if ((isEndpoint && isEndpointStrictValid(item, value, req, meta, doAllBlocks, log)) ||
        item.inError(req, this, value, doAllBlocks, log))
    {
      item.handleMode(true, value, req, item.mode, log, doAllBlocks);
      return true;
    }
    return false;
  }

  private Item getItemFromMetaOrIndex(Metadata meta, String key)
  {
    Item item = getItemFromMetadata(meta, key);
    if (item == null)
    {
      String a = meta.getFromIndex(key);
      if (a == null)
      {
        return null;
      }
      item = getItemFromMetadata(meta, a);
      if (item == null)
      {
        return null;
      }
    }
    return item;
  }

  private boolean isEndpointStrictValid(Item item, String value, ServletRequest req, Metadata meta, boolean doAllBlocks, boolean log)
  {
    if (MetadataEndpoints.isStrictError(req, meta))
    {
      Item.handleStrictError(STRICT_PARAMETER_DETECTED, req, logger, log);
      return true;
    }
    return false;
  }

  private boolean handleChildShield(ServletRequest req, String value, boolean log)
  {
    if (childShield != null)
    {
      if (req == null)
      {
        return childShield.threat(value, log);
      }
      else
      {
        return childShield.threatDetected(req, false, log);
      }
    }
    return false;
  }

  private Item getItemFromMetadata(Metadata meta, String key)
  {
    Item item;
    item = getItem(meta, key);
    if (item == null && regexAlways && !regexAlwaysExclusions.contains(key))
    {
      item = new ItemString();
    }
    return item;
  }

  String getAllowListedValue(String name, AllowListType type, HttpServletRequest req)
  {
    if (name == null || req == null)
    {
      return null;
    }

    if (type == AllowListType.HEADER)
    {
      return getAllowListedHeader(name, req);
    }
    else if (type == AllowListType.COOKIE)
    {
      return getAllowListedCookie(name, req);
    }
    else if (type == AllowListType.PARAMETER)
    {
      return getAllowListedParameter(name, req);
    }
    return null;
  }

  String getAllowListedHeader(String name, HttpServletRequest req)
  {
    Item item = getItemFromMetadata(headers, name);
    if (item != null)
    {
      return req.getHeader(name);
    }
    return null;
  }

  String getAllowListedCookie(String name, HttpServletRequest req)
  {
    Item item = getItemFromMetadata(cookies, name);
    if (item != null)
    {
      Cookie[] cookieValues = req.getCookies();
      if (cookieValues != null)
      {
        for (Cookie c : cookieValues)
        {
          if (c.getName().equals(name))
          {
            return c.getValue();
          }
        }
      }
    }
    return null;
  }

  String getAllowListedParameter(String name, HttpServletRequest req)
  {
    Item item = getItemFromMetadata(parameters, name);
    if (item != null)
    {
      return req.getParameter(name);
    }
    return null;
  }

  Item getItem(Metadata meta, String key)
  {
    Item item;
    if (meta.caseSensitive)
    {
      item = meta.items.get(key);
    }
    else
    {
      item = meta.items.get(key.toLowerCase());
    }
    return item;
  }

  // XML LOAD CODE
  static final String XML_NAME = "name";
  static final String XML_MODE = "mode";
  static final String XML_MIN_LEN = "minLen";
  static final String XML_MAX_LEN = "maxLen";
  static final String XML_CHILD = "child";
  static final String XML_CHILD_SHIELD = "child-shield";
  static final String XML_SHIELD_SETTINGS = "shield-settings";
  static final String XML_REGEX_CONFIG = "regex-config";
  static final String XML_REGEX_ALWAYS_REGEX = "forceStringPatterns";
  static final String XML_REGEX_ALWAYS_REGEX_EXCLUSIONS = "exclusions";
  static final String XML_REGEX_PATTERNS_AUTO = "stringPatterns";
  static final String XML_REGEX_PATTERNS_CUSTOM = "customPatterns";
  static final String XML_KEY = "key";
  static final String XML_VALUE = "value";
  static final String XML_CASE_SENSITIVE = "caseSensitive";
  static final String XML_ENABLED = "enabled";
  static final String SEPARATOR = ":::";

  private void load(Sanwaf sanwaf, Xml xml, Xml shieldXml, Logger logger)
  {
    Xml settingsBlockXml = new Xml(shieldXml.get(XML_SHIELD_SETTINGS));
    name = settingsBlockXml.get(XML_NAME);
    mode = Modes.getMode(settingsBlockXml.get(XML_MODE), Modes.BLOCK);
    maxLen = parseInt(settingsBlockXml.get(XML_MAX_LEN), maxLen);
    if (maxLen == -1)
    {
      maxLen = Integer.MAX_VALUE;
    }
    minLen = parseInt(settingsBlockXml.get(XML_MIN_LEN), minLen);
    if (minLen == -1)
    {
      minLen = 0;
    }
    String childShieldName = settingsBlockXml.get(XML_CHILD);
    if (!childShieldName.isEmpty())
    {
      loadChildShield(sanwaf, xml, childShieldName, logger);
    }

    ItemFactory.setErrorMessages(errorMessages, settingsBlockXml);

    Xml regexBlockXml = new Xml(shieldXml.get(XML_REGEX_CONFIG));
    loadPatterns(regexBlockXml);
    regexMinLen = parseInt(regexBlockXml.get(XML_MIN_LEN), regexMinLen);
    if (regexMinLen == -1)
    {
      regexMinLen = Integer.MAX_VALUE;
    }

    String alwaysBlock = shieldXml.get(XML_REGEX_ALWAYS_REGEX);
    Xml alwaysBlockXml = new Xml(alwaysBlock);
    regexAlways = Boolean.parseBoolean(alwaysBlockXml.get(XML_ENABLED));
    regexAlwaysExclusions = new ArrayList<>();
    if (regexAlways)
    {
      String exclusionsBlock = alwaysBlockXml.get(XML_REGEX_ALWAYS_REGEX_EXCLUSIONS);
      Xml exclusionsBlockXml = new Xml(exclusionsBlock);
      String[] items = exclusionsBlockXml.getAll(ItemFactory.XML_ITEM);
      for (String item : items)
      {
        List<String> list = split(item);
        for (String l : list)
        {
          regexAlwaysExclusions.add(l);
        }
      }
    }
    endpoints = new MetadataEndpoints(this, shieldXml, logger, false);
    endpointsDetect = new MetadataEndpoints(this, shieldXml, logger, true);
    parameters = new Metadata(this, shieldXml, Metadata.XML_PARAMETERS, logger, false);
    parametersDetect = new Metadata(this, shieldXml, Metadata.XML_PARAMETERS, logger, true);
    cookies = new Metadata(this, shieldXml, Metadata.XML_COOKIES, logger, false);
    cookiesDetect = new Metadata(this, shieldXml, Metadata.XML_COOKIES, logger, true);
    headers = new Metadata(this, shieldXml, Metadata.XML_HEADERS, logger, false);
    headersDetect = new Metadata(this, shieldXml, Metadata.XML_HEADERS, logger, true);
  }

  private void loadChildShield(Sanwaf sanwaf, Xml xml, String childShieldName, Logger logger)
  {
    String[] children = xml.getAll(XML_CHILD_SHIELD);
    for (String child : children)
    {
      Xml childXml = new Xml(child);
      Xml settings = new Xml(childXml.get(XML_SHIELD_SETTINGS));
      if (settings.get(XML_NAME).equals(childShieldName))
      {
        childShield = new Shield(sanwaf, xml, new Xml(child), logger);
        break;
      }
    }
  }

  private void loadPatterns(Xml xml)
  {
    String autoBlock = xml.get(XML_REGEX_PATTERNS_AUTO);
    Xml autoBlockXml = new Xml(autoBlock);
    String[] items = autoBlockXml.getAll(ItemFactory.XML_ITEM);
    setRulePattern(items, rulePatterns, rulePatternsDetect, "fail");
    String customBlock = xml.get(XML_REGEX_PATTERNS_CUSTOM);
    Xml customBlockXml = new Xml(customBlock);
    items = customBlockXml.getAll(ItemFactory.XML_ITEM);
    setRulePattern(items, customRulePatterns, customRulePatternsDetect, "pass");
  }

  private void setRulePattern(String[] items, Map<String, Rule> patterns, Map<String, Rule> patternsDetect, String defaultMatch)
  {
    for (String item : items)
    {
      Xml itemBlockXml = new Xml(item);
      String key = itemBlockXml.get(XML_KEY);
      String value = itemBlockXml.get(XML_VALUE);
      Modes m = Modes.getMode(itemBlockXml.get(XML_MODE), Modes.BLOCK);
      List<String> list = split(value);
      for (String l : list)
      {
        if (l.startsWith(REGEX_FILE_MARKER))
        {
          String x = getXmlFileFile(l);
          if (x == null)
          {
            continue;
          }
          l = x;
        }
        String match = itemBlockXml.get(ItemFactory.XML_ITEM_MATCH);
        if (match.isEmpty())
        {
          match = defaultMatch;
        }
        String msg = itemBlockXml.get(ItemFactory.XML_ITEM_MSG);
        Rule r = new Rule(m, Pattern.compile(l, Pattern.CASE_INSENSITIVE), match, msg);
        if (r.mode == Modes.BLOCK)
        {
          patterns.put(key.toLowerCase(), r);
        }
        else
        {
          patternsDetect.put(key.toLowerCase(), r);
        }
      }
    }
  }

  private String getXmlFileFile(String xml)
  {
    String filename = xml.substring(REGEX_FILE_MARKER.length());
    String filekey = null;
    String[] a = xml.split("\\|");
    if (a.length == 2)
    {
      filename = a[0].substring(REGEX_FILE_MARKER.length());
      filekey = a[1];
    }
    else if (a.length != 1)
    {
      logger.error("invalid pattern definition (unable to load specified file):" + xml);
      return null;
    }

    try
    {
      Xml fileXml = new Xml(Shield.class.getResource(filename));
      if (filekey == null)
      {
        return fileXml.toString().trim();
      }
      else
      {
        return fileXml.get(filekey).trim();
      }
    }
    catch (IOException e)
    {
      logger.error("invalid pattern definition (unable to load specified file):" + filename);
    }
    return null;
  }

  private void logStartup()
  {
    StringBuilder sb = new StringBuilder();
    sb.append("Loading Shield: ").append(name).append(mode).append(" - Mode: ").append(mode);
    if (sanwaf.verbose)
    {
      sb.append("\nSettings:\n");
      sb.append("\t").append(XML_MAX_LEN).append("=").append(maxLen).append("\n");
      sb.append("\t").append(XML_MIN_LEN).append("=").append(minLen).append("\n");
      if (childShield != null)
      {
        sb.append("\t").append(XML_CHILD_SHIELD).append("=").append(childShield.name).append("\n");
      }
      sb.append("\t").append("regex ").append(XML_MIN_LEN).append("=").append(regexMinLen).append("\n");
      sb.append("\t").append(MetadataEndpoints.XML_ENDPOINTS).append(".").append(XML_ENABLED).append("=").append(endpoints.enabled).append("\n");
      sb.append("\t").append(MetadataEndpoints.XML_ENDPOINTS).append(".").append(XML_CASE_SENSITIVE).append("=").append(endpoints.caseSensitive).append("\n");
      sb.append("\t").append(Metadata.XML_PARAMETERS).append(".").append(XML_ENABLED).append("=").append(parameters.enabled).append("\n");
      sb.append("\t").append(Metadata.XML_PARAMETERS).append(".").append(XML_CASE_SENSITIVE).append("=").append(parameters.caseSensitive).append("\n");
      sb.append("\t").append(Metadata.XML_COOKIES).append(".").append(XML_ENABLED).append("=").append(cookies.enabled).append("\n");
      sb.append("\t").append(Metadata.XML_COOKIES).append(".").append(XML_CASE_SENSITIVE).append("=").append(cookies.caseSensitive).append("\n");
      sb.append("\t").append(Metadata.XML_HEADERS).append(".").append(XML_ENABLED).append("=").append(headers.enabled).append("\n");
      sb.append("\t").append(Metadata.XML_HEADERS).append(".").append(XML_CASE_SENSITIVE).append("=").append(headers.caseSensitive).append("\n");

      sb.append("\nStringRegexs:\n");
      for (Map.Entry<String, Rule> e : rulePatterns.entrySet())
      {
        sb.append("\t").append(e.getValue().mode).append("\t").append(e.getKey()).append("=").append(e.getValue().pattern).append(FAIL_ON_MATCH).append(e.getValue().failOnMatch).append("\n");
      }
      for (Map.Entry<String, Rule> e : rulePatternsDetect.entrySet())
      {
        sb.append("\t").append(e.getValue().mode).append("\t").append(e.getKey()).append("=").append(e.getValue().pattern).append(FAIL_ON_MATCH).append(e.getValue().failOnMatch).append("\n");
      }

      sb.append("\n" + XML_REGEX_PATTERNS_CUSTOM + ":\n");
      for (Map.Entry<String, Rule> e : customRulePatterns.entrySet())
      {
        sb.append("\t").append(e.getValue().mode).append("\t").append(e.getKey()).append("=").append(e.getValue().pattern).append(FAIL_ON_MATCH).append(e.getValue().failOnMatch).append("\n");
      }
      for (Map.Entry<String, Rule> e : customRulePatternsDetect.entrySet())
      {
        sb.append("\t").append(e.getValue().mode).append("\t").append(e.getKey()).append("=").append(e.getValue().pattern).append(FAIL_ON_MATCH).append(e.getValue().failOnMatch).append("\n");
      }

      if (regexAlways)
      {
        sb.append("\n\tShield Secured List: *Ignored*");
        sb.append("\n\t" + XML_REGEX_ALWAYS_REGEX + "=true (process all parameters)");
        sb.append("\n\tExcept for (exclusion list):\n");
        for (String s : regexAlwaysExclusions)
        {
          sb.append("\t").append(s);
        }
      }
      sb.append("\n");
      if (!regexAlways)
      {
        sb.append("Secured Items:\n");
        appendPItemMapToSB(headers.items, sb, "\tHeaders");
        appendPItemMapToSB(cookies.items, sb, "\tCookies");
        appendPItemMapToSB(parameters.items, sb, "\tParameters");
        sb.append("\tEndpoints\n");
        appendEndpoints(endpoints, endpointsDetect, sb, "\t");
      }
    }
    logger.info(sb.toString());
  }

  static int parseInt(String s, int d)
  {
    try
    {
      return Integer.parseInt(s);
    }
    catch (NumberFormatException nfe)
    {
      return d;
    }
  }

  static void appendEndpoints(MetadataEndpoints endpoints, MetadataEndpoints endpointsDetect, StringBuilder sb, String label)
  {
    Iterator<Map.Entry<String, Metadata>> it = endpoints.endpointParametersBlock.entrySet().iterator();
    appendItemToSb(sb, label, it);

    it = endpointsDetect.endpointParametersDetect.entrySet().iterator();
    appendItemToSb(sb, label, it);
  }

  private static void appendItemToSb(StringBuilder sb, String label, Iterator<Map.Entry<String, Metadata>> it)
  {
    while (it.hasNext())
    {
      Map.Entry<String, Metadata> pair = it.next();
      appendPItemMapToSB(pair.getValue().items, sb, label + pair.getKey());
    }
  }

  static void appendPItemMapToSB(Map<String, Item> map, StringBuilder sb, String label)
  {
    sb.append(label);
    if (map != null && !map.isEmpty())
    {
      Iterator<?> it = map.entrySet().iterator();
      while (it.hasNext())
      {
        @SuppressWarnings("unchecked")
        Map.Entry<String, Item> e = (Map.Entry<String, Item>) it.next();
        sb.append("\n\t\t" + e.getKey() + "=" + e.getValue());
      }
    }
    sb.append("\n");
  }

  static List<String> split(String s)
  {
    List<String> out = new ArrayList<>();
    if (s != null && !s.isEmpty())
    {
      String[] vs = s.split(SEPARATOR);
      for (String v : vs)
      {
        if (!v.isEmpty())
        {
          out.add(v);
        }
      }
    }
    return out;
  }
}

class Rule
{
  Modes mode;
  Pattern pattern;
  boolean failOnMatch = true;
  String msg;

  Rule()
  {
    mode = Modes.BLOCK;
  }

  Rule(Modes mode, Pattern pattern, String match, String msg)
  {
    this.mode = mode;
    this.pattern = pattern;
    if ("pass".equalsIgnoreCase(match))
    {
      failOnMatch = false;
    }
    this.msg = msg;
  }
}
