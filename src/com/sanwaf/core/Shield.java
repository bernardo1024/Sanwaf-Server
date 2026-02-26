package com.sanwaf.core;

import com.sanwaf.core.Sanwaf.AllowListType;
import com.sanwaf.log.Logger;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

final class Shield
{
  private static final String STRICT_PARAMETER_DETECTED = "URI Strict Parameter Error - Unknown Parameter Detected";
  private static final String FAIL_ON_MATCH = "\tfailOnMatch=";
  private static final String REGEX_FILE_MARKER = "file=";
  final Sanwaf sanwaf;
  final Logger logger;
  final String name;
  final Modes mode;
  final Shield childShield;
  final int minLen;
  final int maxLen;
  final int regexMinLen;
  final boolean regexAlways;
  final Map<String, String> errorMessages;
  final Set<String> regexAlwaysExclusions;
  final Map<String, Rule> rulePatterns;
  final Map<String, Rule> customRulePatterns;
  final Map<String, Rule> rulePatternsDetect;
  final Map<String, Rule> customRulePatternsDetect;
  final Metadata parameters;
  final Metadata cookies;
  final Metadata headers;
  final boolean endpointsEnabled;
  final boolean endpointsCaseSensitive;
  final Map<String, Metadata> endpointParameters;

  Shield(Sanwaf sanwaf, Xml xml, Xml shieldXml, Logger logger, boolean verbose)
  {
    this.sanwaf = sanwaf;
    this.logger = logger;

    Xml settingsBlockXml = new Xml(shieldXml.get(XML_SHIELD_SETTINGS));
    this.name = settingsBlockXml.get(XML_NAME);
    this.mode = Modes.getMode(settingsBlockXml.get(XML_MODE), Modes.BLOCK);

    int parsedMaxLen = parseInt(settingsBlockXml.get(XML_MAX_LEN), Integer.MAX_VALUE);
    this.maxLen = (parsedMaxLen == -1) ? Integer.MAX_VALUE : parsedMaxLen;

    int parsedMinLen = parseInt(settingsBlockXml.get(XML_MIN_LEN), 0);
    this.minLen = (parsedMinLen == -1) ? 0 : parsedMinLen;

    String childShieldName = settingsBlockXml.get(XML_CHILD);
    this.childShield = childShieldName.isEmpty() ? null : findChildShield(sanwaf, xml, childShieldName, logger, verbose);

    Map<String, String> em = new HashMap<>(22); // 16 entries; (16/0.75)+1 avoids resize
    ItemFactory.setErrorMessages(em, settingsBlockXml);
    this.errorMessages = Collections.unmodifiableMap(em);

    Xml regexBlockXml = new Xml(shieldXml.get(XML_REGEX_CONFIG));
    Map<String, Rule> rp = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    Map<String, Rule> crp = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    Map<String, Rule> rpd = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    Map<String, Rule> crpd = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    loadPatterns(regexBlockXml, rp, crp, rpd, crpd);
    this.rulePatterns = Collections.unmodifiableMap(rp);
    this.customRulePatterns = Collections.unmodifiableMap(crp);
    this.rulePatternsDetect = Collections.unmodifiableMap(rpd);
    this.customRulePatternsDetect = Collections.unmodifiableMap(crpd);

    int parsedRegexMinLen = parseInt(regexBlockXml.get(XML_MIN_LEN), 0);
    this.regexMinLen = (parsedRegexMinLen == -1) ? Integer.MAX_VALUE : parsedRegexMinLen;

    String alwaysBlock = shieldXml.get(XML_REGEX_ALWAYS_REGEX);
    Xml alwaysBlockXml = new Xml(alwaysBlock);
    this.regexAlways = Boolean.parseBoolean(alwaysBlockXml.get(XML_ENABLED));
    this.regexAlwaysExclusions = regexAlways
        ? Collections.unmodifiableSet(loadRegexExclusions(alwaysBlockXml))
        : Collections.emptySet();

    Metadata.ParsedMetadataXml epParsed = Metadata.parseMetadataXml(shieldXml, Metadata.XML_ENDPOINTS);
    this.endpointsEnabled = epParsed.enabled;
    this.endpointsCaseSensitive = epParsed.caseSensitive;
    this.endpointParameters = Metadata.loadEndpoints(this, epParsed, epParsed.caseSensitive, logger);
    this.parameters = new Metadata(this, shieldXml, Metadata.XML_PARAMETERS, logger);
    this.cookies = new Metadata(this, shieldXml, Metadata.XML_COOKIES, logger);
    this.headers = new Metadata(this, shieldXml, Metadata.XML_HEADERS, logger);

    logStartup(verbose);
  }

  boolean threatDetected(ServletRequest req, boolean doAllBlocks, boolean log)
  {
    return ((endpointsEnabled && endpointsThreatDetected(req, doAllBlocks, log)) ||
        (parameters.enabled && parameterThreatDetected(req, doAllBlocks, log)) ||
        (headers.enabled && headerThreatDetected(req, doAllBlocks, log)) ||
        (cookies.enabled && cookieThreatDetected(req, doAllBlocks, log)));
  }

  private boolean endpointsThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log)
  {
    HttpServletRequest hreq = (HttpServletRequest) req;
    String uri = hreq.getRequestURI();

    Metadata meta = endpointParameters.get(uri);
    if (meta == null || meta.endpointMode == Modes.DISABLED)
    {
      return false;
    }

    if (!doAllBlocks && meta.endpointMode != Modes.BLOCK)
    {
      return false;
    }

    boolean strictError = meta.isStrictError(req);
    if (strictError)
    {
      JsonFormatter.handleStrictError(STRICT_PARAMETER_DETECTED, req, logger, log);
      if (!doAllBlocks)
      {
        return true;
      }
    }

    boolean threat = strictError;
    Enumeration<?> names = req.getParameterNames();
    while (names.hasMoreElements())
    {
      String k = (String) names.nextElement();
      String[] values = req.getParameterValues(k);
      for (String v : values)
      {
        if (threat(req, meta, k, v, true, doAllBlocks, log))
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

  private boolean parameterThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log)
  {
    boolean retstring = false;
    Enumeration<?> names = req.getParameterNames();
    while (names.hasMoreElements())
    {
      String k = (String) names.nextElement();
      String[] values = req.getParameterValues(k);
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
    HttpServletRequest hreq = (HttpServletRequest) req;
    Enumeration<?> names = hreq.getHeaderNames();
    while (names.hasMoreElements())
    {
      String s = (String) names.nextElement();
      Enumeration<?> headerValues = hreq.getHeaders(s);
      while (headerValues.hasMoreElements())
      {
        if (threat(req, headers, s, (String) headerValues.nextElement(), false, doAllBlocks, log))
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

  // Convenience overload: assumes isEndpoint=false and log=false
  boolean threat(ServletRequest req, Metadata meta, String key, String value)
  {
    return threat(req, meta, key, value, false, false, false, false);
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
          item = ItemString.DEFAULT_INSTANCE;
        }
        else
        {
          return false;
        }
      }
    }
    else
    {
      item = ItemString.DEFAULT_INSTANCE;
    }

    if (item.required && value.isEmpty())
    {
      return item.handleMode(true, value, req, item.mode, log, doAllBlocks, null);
    }

    String relmsg = item.isRelateValid(value, req, meta);
    if (relmsg != null)
    {
      return item.handleMode(true, value, req, item.mode, log, doAllBlocks, relmsg);
    }

    if (item.inError(req, this, value, doAllBlocks, log))
    {
      return item.handleMode(true, value, req, item.mode, log, doAllBlocks, null);
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
    }
    return item;
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
      item = ItemString.DEFAULT_INSTANCE;
    }
    return item;
  }

  String getAllowListedValue(String name, AllowListType type, HttpServletRequest req)
  {
    if (name == null || type == null || req == null)
    {
      return null;
    }

    switch (type)
    {
    case HEADER:
      return getAllowListedHeader(name, req);
    case COOKIE:
      return getAllowListedCookie(name, req);
    case PARAMETER:
      return getAllowListedParameter(name, req);
    default:
      return null;
    }
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
    return meta.items.get(key);
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
  private static final Pattern SEPARATOR_PATTERN = Pattern.compile(SEPARATOR);
  private static final Pattern PIPE_PATTERN = Pattern.compile("\\|");

  private static Shield findChildShield(Sanwaf sanwaf, Xml xml, String childShieldName, Logger logger, boolean verbose)
  {
    String[] children = xml.getAll(XML_CHILD_SHIELD);
    for (String child : children)
    {
      Xml childXml = new Xml(child);
      Xml settings = new Xml(childXml.get(XML_SHIELD_SETTINGS));
      if (settings.get(XML_NAME).equals(childShieldName))
      {
        return new Shield(sanwaf, xml, new Xml(child), logger, verbose);
      }
    }
    return null;
  }

  private static Set<String> loadRegexExclusions(Xml alwaysBlockXml)
  {
    Set<String> exclusions = new LinkedHashSet<>();
    String exclusionsBlock = alwaysBlockXml.get(XML_REGEX_ALWAYS_REGEX_EXCLUSIONS);
    Xml exclusionsBlockXml = new Xml(exclusionsBlock);
    String[] items = exclusionsBlockXml.getAll(ItemFactory.XML_ITEM);
    for (String item : items)
    {
      List<String> list = split(item);
      exclusions.addAll(list);
    }
    return exclusions;
  }

  private void loadPatterns(Xml xml, Map<String, Rule> rulePatterns, Map<String, Rule> customRulePatterns,
      Map<String, Rule> rulePatternsDetect, Map<String, Rule> customRulePatternsDetect)
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
          patterns.put(key, r);
        }
        else
        {
          patternsDetect.put(key, r);
        }
      }
    }
  }

  private String getXmlFileFile(String xml)
  {
    String filename = xml.substring(REGEX_FILE_MARKER.length());
    String filekey = null;
    String[] a = PIPE_PATTERN.split(xml);
    if (a.length == 2)
    {
      filename = a[0].substring(REGEX_FILE_MARKER.length());
      filekey = a[1];
    }
    else if (a.length != 1)
    {
      if (logger.isErrorEnabled())
      {
        logger.error("invalid pattern definition (unable to load specified file):" + xml);
      }
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
      if (logger.isErrorEnabled())
      {
        logger.error("invalid pattern definition (unable to load specified file):" + filename);
      }
    }
    return null;
  }

  private void logStartup(boolean verbose)
  {
    if (!logger.isInfoEnabled())
    {
      return;
    }
    StringBuilder sb = new StringBuilder();
    sb.append("Loading Shield: ").append(name).append(" - Mode: ").append(mode);
    if (verbose)
    {
      sb.append("\nSettings:\n");
      sb.append("\t").append(XML_MAX_LEN).append("=").append(maxLen).append("\n");
      sb.append("\t").append(XML_MIN_LEN).append("=").append(minLen).append("\n");
      if (childShield != null)
      {
        sb.append("\t").append(XML_CHILD_SHIELD).append("=").append(childShield.name).append("\n");
      }
      sb.append("\t").append("regex ").append(XML_MIN_LEN).append("=").append(regexMinLen).append("\n");
      appendMetadataSettings(sb, Metadata.XML_ENDPOINTS, endpointsEnabled, endpointsCaseSensitive);
      appendMetadataSettings(sb, Metadata.XML_PARAMETERS, parameters.enabled, parameters.caseSensitive);
      appendMetadataSettings(sb, Metadata.XML_COOKIES, cookies.enabled, cookies.caseSensitive);
      appendMetadataSettings(sb, Metadata.XML_HEADERS, headers.enabled, headers.caseSensitive);

      sb.append("\nStringRegexs:\n");
      appendRules(sb, rulePatterns);
      appendRules(sb, rulePatternsDetect);

      sb.append("\n").append(XML_REGEX_PATTERNS_CUSTOM).append(":\n");
      appendRules(sb, customRulePatterns);
      appendRules(sb, customRulePatternsDetect);

      if (regexAlways)
      {
        sb.append("\n\tShield Secured List: *Ignored*");
        sb.append("\n\t").append(XML_REGEX_ALWAYS_REGEX).append("=true (process all parameters)");
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
        appendEndpoints(endpointParameters, sb, "\t");
      }
    }
    logger.info(sb.toString());
  }

  private static void appendRules(StringBuilder sb, Map<String, Rule> rules)
  {
    for (Map.Entry<String, Rule> e : rules.entrySet())
    {
      sb.append("\t").append(e.getValue().mode).append("\t").append(e.getKey()).append("=").append(e.getValue().pattern).append(FAIL_ON_MATCH).append(e.getValue().failOnMatch).append("\n");
    }
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

  static double parseDouble(String s, double d)
  {
    try
    {
      return Double.parseDouble(s);
    }
    catch (NumberFormatException nfe)
    {
      return d;
    }
  }

  static void appendEndpoints(Map<String, Metadata> endpointParameters, StringBuilder sb, String label)
  {
    appendItemToSb(sb, label, endpointParameters);
  }

  private static void appendItemToSb(StringBuilder sb, String label, Map<String, Metadata> map)
  {
    for (Map.Entry<String, Metadata> pair : map.entrySet())
    {
      appendPItemMapToSB(pair.getValue().items, sb, label, pair.getKey());
    }
  }

  static void appendPItemMapToSB(Map<String, Item> map, StringBuilder sb, String label)
  {
    appendPItemMapToSB(map, sb, label, "");
  }

  static void appendPItemMapToSB(Map<String, Item> map, StringBuilder sb, String label, String labelSuffix)
  {
    sb.append(label).append(labelSuffix);
    if (map != null && !map.isEmpty())
    {
      for (Map.Entry<String, Item> e : map.entrySet())
      {
        sb.append("\n\t\t").append(e.getKey()).append("=").append(e.getValue());
      }
    }
    sb.append("\n");
  }

  private static void appendMetadataSettings(StringBuilder sb, String type, boolean enabled, boolean caseSensitive)
  {
    sb.append("\t").append(type).append(".").append(XML_ENABLED).append("=").append(enabled).append("\n");
    sb.append("\t").append(type).append(".").append(XML_CASE_SENSITIVE).append("=").append(caseSensitive).append("\n");
  }

  static List<String> split(String s)
  {
    List<String> out = new ArrayList<>();
    if (s != null && !s.isEmpty())
    {
      String[] vs = SEPARATOR_PATTERN.split(s);
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
  final Modes mode;
  final Pattern pattern;
  final boolean failOnMatch;
  final String msg;
  Rule()
  {
    this.mode = Modes.BLOCK;
    this.pattern = null;
    this.failOnMatch = true;
    this.msg = null;
  }

  Rule(Modes mode, Pattern pattern, String match, String msg)
  {
    this.mode = mode;
    this.pattern = pattern;
    this.failOnMatch = !"pass".equalsIgnoreCase(match);
    this.msg = msg;
  }
}
