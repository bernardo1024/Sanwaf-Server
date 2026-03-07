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

/**
 * A named collection of security rules that inspects HTTP request parameters,
 * headers, and cookies for threats. Each Shield is configured from an XML block
 * and holds regex patterns, item definitions, error messages, and optional
 * endpoint-specific metadata. A Shield may delegate to a {@link #childShield}
 * when a value falls outside its configured length bounds.
 */
final class Shield {
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
  final Rule[] rulePatternsArray;
  final Rule[] rulePatternsDetectArray;
  final boolean canSkipByCharScan;
  final Metadata parameters;
  final Metadata cookies;
  final Metadata headers;
  final boolean endpointsEnabled;
  final boolean endpointsCaseSensitive;
  final Map<String, Metadata> endpointParameters;

  /**
   * Constructs a Shield by parsing its configuration from XML.
   *
   * @param sanwaf    the parent Sanwaf instance
   * @param xml       the root XML document (used to resolve child shields)
   * @param shieldXml the XML block specific to this shield
   * @param logger    logger for startup and runtime messages
   * @param verbose   whether to log detailed startup information
   */
  Shield(Sanwaf sanwaf, Xml xml, Xml shieldXml, Logger logger, boolean verbose) {
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
    this.rulePatternsArray = rp.values().toArray(new Rule[0]);
    this.rulePatternsDetectArray = rpd.values().toArray(new Rule[0]);

    boolean allFailOnMatch = true;
    for (Rule r : rulePatternsArray)
      if (!r.failOnMatch) {
        allFailOnMatch = false;
        break;
      }
    if (allFailOnMatch)
      for (Rule r : rulePatternsDetectArray)
        if (!r.failOnMatch) {
          allFailOnMatch = false;
          break;
        }

    boolean canSkip = allFailOnMatch && (rulePatternsArray.length > 0 || rulePatternsDetectArray.length > 0);
    if (canSkip) {
      for (Rule r : rulePatternsArray) {
        if (r.pattern != null && patternLacksXssChar(r.pattern)) {
          canSkip = false;
          break;
        }
      }
    }
    if (canSkip) {
      for (Rule r : rulePatternsDetectArray) {
        if (r.pattern != null && patternLacksXssChar(r.pattern)) {
          canSkip = false;
          break;
        }
      }
    }
    this.canSkipByCharScan = canSkip;

    int parsedRegexMinLen = parseInt(regexBlockXml.get(XML_MIN_LEN), 0);
    this.regexMinLen = (parsedRegexMinLen == -1) ? Integer.MAX_VALUE : parsedRegexMinLen;

    String alwaysBlock = shieldXml.get(XML_REGEX_ALWAYS_REGEX);
    Xml alwaysBlockXml = new Xml(alwaysBlock);
    this.regexAlways = Boolean.parseBoolean(alwaysBlockXml.get(XML_ENABLED));
    this.regexAlwaysExclusions = regexAlways ? Collections.unmodifiableSet(loadRegexExclusions(alwaysBlockXml)) : Collections.emptySet();

    Metadata.ParsedMetadataXml epParsed = Metadata.parseMetadataXml(shieldXml, Metadata.XML_ENDPOINTS);
    this.endpointsEnabled = epParsed.enabled;
    this.endpointsCaseSensitive = epParsed.caseSensitive;
    this.endpointParameters = Metadata.loadEndpoints(this, epParsed, epParsed.caseSensitive, logger);
    this.parameters = new Metadata(this, shieldXml, Metadata.XML_PARAMETERS, logger);
    this.cookies = new Metadata(this, shieldXml, Metadata.XML_COOKIES, logger);
    this.headers = new Metadata(this, shieldXml, Metadata.XML_HEADERS, logger);

    logStartup(verbose);
  }

  /**
   * Scans the request for threats across endpoints, parameters, headers, and
   * cookies.
   *
   * @param req         the servlet request to inspect
   * @param doAllBlocks if {@code true}, continues scanning after the first
   *                    threat to collect all violations; otherwise short-circuits
   * @param log         whether to log detected threats
   * @return {@code true} if at least one threat was detected
   */
  boolean threatDetected(ServletRequest req, boolean doAllBlocks, boolean log) {
    return ((endpointsEnabled && endpointsThreatDetected(req, doAllBlocks, log)) || (parameters.enabled && parameterThreatDetected(req, doAllBlocks, log))
        || (headers.enabled && headerThreatDetected(req, doAllBlocks, log)) || (cookies.enabled && cookieThreatDetected(req, doAllBlocks, log)));
  }

  /**
   * Checks endpoint-specific items for threats. If the endpoint enforces strict
   * mode, unknown parameters are flagged before item-level scanning begins.
   *
   * @param req         the servlet request to inspect
   * @param doAllBlocks if {@code true}, collects all violations instead of
   *                    short-circuiting
   * @param log         whether to log detected threats
   * @return {@code true} if at least one threat was detected
   */
  private boolean endpointsThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log) {
    HttpServletRequest hreq = (HttpServletRequest) req;
    String uri = hreq.getRequestURI();

    Metadata meta = endpointParameters.get(uri);
    if (meta == null || meta.endpointMode == Modes.DISABLED) {
      return false;
    }

    if (!doAllBlocks && meta.endpointMode != Modes.BLOCK) {
      return false;
    }

    boolean strictError = meta.isStrictError(req);
    if (strictError) {
      JsonFormatter.handleStrictError(STRICT_PARAMETER_DETECTED, req, logger, log);
      if (!doAllBlocks) {
        return true;
      }
    }

    boolean threat = strictError;
    Enumeration<?> names = req.getParameterNames();
    while (names.hasMoreElements()) {
      String k = (String) names.nextElement();
      String[] values = req.getParameterValues(k);
      for (String v : values) {
        if (threat(req, meta, k, v, true, doAllBlocks, log)) {
          if (!doAllBlocks) {
            return true;
          }
          threat = true;
        }
      }
    }
    return threat;
  }

  /**
   * Scans all request parameters against this shield's parameter metadata.
   *
   * @param req         the servlet request to inspect
   * @param doAllBlocks if {@code true}, collects all violations instead of
   *                    short-circuiting
   * @param log         whether to log detected threats
   * @return {@code true} if at least one threat was detected
   */
  private boolean parameterThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log) {
    boolean threat = false;
    Enumeration<?> names = req.getParameterNames();
    while (names.hasMoreElements()) {
      String name = (String) names.nextElement();
      for (String value : req.getParameterValues(name)) {
        if (threat(req, parameters, name, value, false, doAllBlocks, log)) {
          if (!doAllBlocks) {
            return true;
          }
          threat = true;
        }
      }
    }
    return threat;
  }

  /**
   * Scans all request headers against this shield's header metadata.
   *
   * @param req         the servlet request to inspect
   * @param doAllBlocks if {@code true}, collects all violations instead of
   *                    short-circuiting
   * @param log         whether to log detected threats
   * @return {@code true} if at least one threat was detected
   */
  private boolean headerThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log) {
    HttpServletRequest httpReq = (HttpServletRequest) req;
    boolean threat = false;
    Enumeration<String> names = httpReq.getHeaderNames();
    while (names.hasMoreElements()) {
      String name = names.nextElement();
      Enumeration<String> values = httpReq.getHeaders(name);
      while (values.hasMoreElements()) {
        if (threat(req, headers, name, values.nextElement(), false, doAllBlocks, log)) {
          if (!doAllBlocks) {
            return true;
          }
          threat = true;
        }
      }
    }
    return threat;
  }

  /**
   * Scans all request cookies against this shield's cookie metadata.
   *
   * @param req         the servlet request to inspect
   * @param doAllBlocks if {@code true}, collects all violations instead of
   *                    short-circuiting
   * @param log         whether to log detected threats
   * @return {@code true} if at least one threat was detected
   */
  private boolean cookieThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log) {
    boolean threat = false;
    Cookie[] cookieArray = ((HttpServletRequest) req).getCookies();
    if (cookieArray == null) {
      return false;
    }
    for (Cookie c : cookieArray) {
      if (threat(req, cookies, c.getName(), c.getValue(), false, doAllBlocks, log)) {
        if (!doAllBlocks) {
          return true;
        }
        threat = true;
      }
    }
    return threat;
  }

  /**
   * Tests a standalone value for threats using default string-type validation.
   *
   * @param v   the value to test
   * @param log whether to log a detected threat
   * @return {@code true} if the value is a threat
   */
  boolean threat(String v, boolean log) {
    return threat(null, null, "", v, false, false, log);
  }

  /**
   * Convenience overload that assumes {@code isEndpoint=false} and
   * {@code log=false}.
   *
   * @param req   the servlet request (may be {@code null})
   * @param meta  metadata containing item definitions
   * @param key   the parameter/header/cookie name
   * @param value the value to test
   * @return {@code true} if the value is a threat
   */
  boolean threat(ServletRequest req, Metadata meta, String key, String value) {
    return threat(req, meta, key, value, false, false, false);
  }

  /**
   * Tests a value for threats within a request context, using default
   * string-type validation.
   *
   * @param req   the servlet request
   * @param value the value to test
   * @param log   whether to log a detected threat
   * @return {@code true} if the value is a threat
   */
  boolean threat(ServletRequest req, String value, boolean log) {
    return threat(req, null, "", value, false, false, log);
  }

  /**
   * Core threat-detection method. Resolves the {@link Item} for the given key,
   * validates length bounds, required fields, related-field constraints, and
   * item-specific error rules. Delegates to the child shield when the value
   * falls outside this shield's length range.
   *
   * @param req         the servlet request (may be {@code null})
   * @param meta        metadata containing item definitions (may be {@code null})
   * @param key         the parameter/header/cookie name
   * @param value       the value to test
   * @param isEndpoint  whether this check originates from endpoint processing
   * @param doAllBlocks if {@code true}, continues after first error
   * @param log         whether to log a detected threat
   * @return {@code true} if the value is a threat
   */
  boolean threat(ServletRequest req, Metadata meta, String key, String value, boolean isEndpoint, boolean doAllBlocks, boolean log) {
    if (value == null) {
      return false;
    }
    int len = value.length();
    if (len < minLen || len > maxLen) {
      return handleChildShield(req, value, log);
    }
    Item item;
    if (meta != null) {
      item = getItemFromMetaOrIndex(meta, key);
      if (item == null) {
        return false;
      }
    } else {
      item = ItemString.DEFAULT_INSTANCE;
    }

    if (item.required && value.isEmpty()) {
      return item.handleMode(value, req, item.mode, log, doAllBlocks, null);
    }

    if (item.related != null && !item.related.isEmpty()) {
      String relMsg = item.isRelateValid(value, req, meta);
      if (relMsg != null) {
        return item.handleMode(value, req, item.mode, log, doAllBlocks, relMsg);
      }
    }

    if (item.inError(req, this, value, doAllBlocks, log)) {
      return item.handleMode(value, req, item.mode, log, doAllBlocks, null);
    }
    return false;
  }

  /**
   * Looks up an {@link Item} by key, falling back to the metadata wildcard
   * index when no direct match is found.
   *
   * @param meta the metadata to search
   * @param key  the parameter/header/cookie name
   * @return the matching item, or {@code null} if none
   */
  private Item getItemFromMetaOrIndex(Metadata meta, String key) {
    Item item = getItemFromMetadata(meta, key);
    if (item == null) {
      String a = meta.getFromIndex(key);
      if (a == null) {
        return null;
      }
      item = getItemFromMetadata(meta, a);
    }
    return item;
  }

  /**
   * Delegates threat detection to the child shield, if one is configured.
   *
   * @param req   the servlet request (may be {@code null})
   * @param value the value to test
   * @param log   whether to log a detected threat
   * @return {@code true} if the child shield detects a threat
   */
  private boolean handleChildShield(ServletRequest req, String value, boolean log) {
    if (childShield != null) {
      if (req == null) {
        return childShield.threat(value, log);
      } else {
        return childShield.threatDetected(req, false, log);
      }
    }
    return false;
  }

  /**
   * Retrieves an {@link Item} from metadata, falling back to a default
   * string item when {@link #regexAlways} is enabled and the key is not
   * excluded.
   *
   * @param meta the metadata to search
   * @param key  the parameter/header/cookie name
   * @return the matching item, or {@code null} if the key is not secured
   */
  private Item getItemFromMetadata(Metadata meta, String key) {
    Item item;
    item = getItem(meta, key);
    if (item == null && regexAlways && !regexAlwaysExclusions.contains(key)) {
      item = ItemString.DEFAULT_INSTANCE;
    }
    return item;
  }

  /**
   * Returns the value of a request attribute (header, cookie, or parameter)
   * if it is configured as an allow-listed item in this shield.
   *
   * @param name the attribute name
   * @param type the attribute type (HEADER, COOKIE, or PARAMETER)
   * @param req  the HTTP request
   * @return the attribute value if allow-listed, or {@code null}
   */
  String getAllowListedValue(String name, AllowListType type, HttpServletRequest req) {
    if (name == null || type == null || req == null) {
      return null;
    }

    switch (type) {
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

  /**
   * Returns the header value if the named header is allow-listed.
   *
   * @param name the header name
   * @param req  the HTTP request
   * @return the header value, or {@code null} if not allow-listed
   */
  String getAllowListedHeader(String name, HttpServletRequest req) {
    Item item = getItemFromMetadata(headers, name);
    if (item != null) {
      return req.getHeader(name);
    }
    return null;
  }

  /**
   * Returns the cookie value if the named cookie is allow-listed.
   *
   * @param name the cookie name
   * @param req  the HTTP request
   * @return the cookie value, or {@code null} if not allow-listed or absent
   */
  String getAllowListedCookie(String name, HttpServletRequest req) {
    Item item = getItemFromMetadata(cookies, name);
    if (item != null) {
      Cookie[] cookieValues = req.getCookies();
      if (cookieValues != null) {
        for (Cookie c : cookieValues) {
          if (c.getName().equals(name)) {
            return c.getValue();
          }
        }
      }
    }
    return null;
  }

  /**
   * Returns the parameter value if the named parameter is allow-listed.
   *
   * @param name the parameter name
   * @param req  the HTTP request
   * @return the parameter value, or {@code null} if not allow-listed
   */
  String getAllowListedParameter(String name, HttpServletRequest req) {
    Item item = getItemFromMetadata(parameters, name);
    if (item != null) {
      return req.getParameter(name);
    }
    return null;
  }

  /**
   * Retrieves an {@link Item} from the given metadata by key.
   *
   * @param meta the metadata to search
   * @param key  the item key
   * @return the matching item, or {@code null} if not found
   */
  Item getItem(Metadata meta, String key) {
    return meta.getItem(key);
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

  /**
   * Searches the XML document for a child-shield block whose name matches the
   * given name, and constructs it.
   *
   * @param sanwaf          the parent Sanwaf instance
   * @param xml             the root XML document
   * @param childShieldName the name of the child shield to find
   * @param logger          logger for startup messages
   * @param verbose         whether to log detailed startup information
   * @return the matching child Shield, or {@code null} if not found
   */
  private static Shield findChildShield(Sanwaf sanwaf, Xml xml, String childShieldName, Logger logger, boolean verbose) {
    String[] children = xml.getAll(XML_CHILD_SHIELD);
    for (String child : children) {
      Xml childXml = new Xml(child);
      Xml settings = new Xml(childXml.get(XML_SHIELD_SETTINGS));
      if (settings.get(XML_NAME).equals(childShieldName)) {
        return new Shield(sanwaf, xml, new Xml(child), logger, verbose);
      }
    }
    return null;
  }

  /**
   * Parses the exclusion list for the "force string patterns" (regexAlways)
   * feature from the given XML block.
   *
   * @param alwaysBlockXml the XML block containing exclusion items
   * @return a set of parameter names to exclude from forced regex scanning
   */
  private static Set<String> loadRegexExclusions(Xml alwaysBlockXml) {
    Set<String> exclusions = new LinkedHashSet<>();
    String exclusionsBlock = alwaysBlockXml.get(XML_REGEX_ALWAYS_REGEX_EXCLUSIONS);
    Xml exclusionsBlockXml = new Xml(exclusionsBlock);
    String[] items = exclusionsBlockXml.getAll(ItemFactory.XML_ITEM);
    for (String item : items) {
      List<String> list = split(item);
      exclusions.addAll(list);
    }
    return exclusions;
  }

  /**
   * Loads both standard (string) and custom regex patterns from the
   * regex-config XML block, populating the block and detect maps.
   *
   * @param xml                     the regex-config XML block
   * @param rulePatterns            destination for standard block-mode patterns
   * @param customRulePatterns      destination for custom block-mode patterns
   * @param rulePatternsDetect      destination for standard detect-mode patterns
   * @param customRulePatternsDetect destination for custom detect-mode patterns
   */
  private void loadPatterns(Xml xml, Map<String, Rule> rulePatterns, Map<String, Rule> customRulePatterns, Map<String, Rule> rulePatternsDetect, Map<String, Rule> customRulePatternsDetect) {
    String autoBlock = xml.get(XML_REGEX_PATTERNS_AUTO);
    Xml autoBlockXml = new Xml(autoBlock);
    String[] items = autoBlockXml.getAll(ItemFactory.XML_ITEM);
    setRulePattern(items, rulePatterns, rulePatternsDetect, "fail");
    String customBlock = xml.get(XML_REGEX_PATTERNS_CUSTOM);
    Xml customBlockXml = new Xml(customBlock);
    items = customBlockXml.getAll(ItemFactory.XML_ITEM);
    setRulePattern(items, customRulePatterns, customRulePatternsDetect, "pass");
  }

  /**
   * Parses individual regex item XML strings into {@link Rule} objects and
   * files them into the appropriate block or detect map based on mode.
   *
   * @param items          raw XML item strings to parse
   * @param patterns       destination for block-mode rules
   * @param patternsDetect destination for detect-mode rules
   * @param defaultMatch   default match behavior ("fail" or "pass") when not
   *                       specified in the item
   */
  private void setRulePattern(String[] items, Map<String, Rule> patterns, Map<String, Rule> patternsDetect, String defaultMatch) {
    for (String item : items) {
      Xml itemBlockXml = new Xml(item);
      String key = itemBlockXml.get(XML_KEY);
      String value = itemBlockXml.get(XML_VALUE);
      Modes m = Modes.getMode(itemBlockXml.get(XML_MODE), Modes.BLOCK);
      List<String> list = split(value);
      for (String l : list) {
        if (l.startsWith(REGEX_FILE_MARKER)) {
          String x = getXmlFileFile(l);
          if (x == null) {
            continue;
          }
          l = x;
        }
        String match = itemBlockXml.get(ItemFactory.XML_ITEM_MATCH);
        if (match.isEmpty()) {
          match = defaultMatch;
        }
        String msg = itemBlockXml.get(ItemFactory.XML_ITEM_MSG);
        Rule r = new Rule(m, Pattern.compile(l, Pattern.CASE_INSENSITIVE), match, msg);
        if (r.mode == Modes.DISABLED || r.pattern == null) {
          continue;
        }
        if (r.mode == Modes.BLOCK) {
          patterns.put(key, r);
        } else {
          patternsDetect.put(key, r);
        }
      }
    }
  }

  /**
   * Resolves a {@code file=<path>} or {@code file=<path>|<key>} reference
   * to regex content. Loads the file as XML and returns either the full
   * content or the value of a specific key.
   *
   * @param xml the file reference string (e.g., {@code file=patterns.xml|xss})
   * @return the resolved regex string, or {@code null} on failure
   */
  private String getXmlFileFile(String xml) {
    String filename = xml.substring(REGEX_FILE_MARKER.length());
    String filekey = null;
    String[] a = PIPE_PATTERN.split(xml);
    if (a.length == 2) {
      filename = a[0].substring(REGEX_FILE_MARKER.length());
      filekey = a[1];
    } else if (a.length != 1) {
      if (logger.isErrorEnabled()) {
        logger.error("invalid pattern definition (unable to load specified file):" + xml);
      }
      return null;
    }

    try {
      Xml fileXml = new Xml(Shield.class.getResource(filename));
      if (filekey == null) {
        return fileXml.toString().trim();
      } else {
        return fileXml.get(filekey).trim();
      }
    } catch (IOException e) {
      if (logger.isErrorEnabled()) {
        logger.error("invalid pattern definition (unable to load specified file):" + filename);
      }
    }
    return null;
  }

  /**
   * Logs shield configuration at startup. When verbose, includes settings,
   * regex patterns, secured items, and endpoints.
   *
   * @param verbose whether to include detailed configuration in the log
   */
  private void logStartup(boolean verbose) {
    if (!logger.isInfoEnabled()) {
      return;
    }
    StringBuilder sb = new StringBuilder();
    sb.append("Loading Shield: ").append(name).append(" - Mode: ").append(mode);
    if (verbose) {
      sb.append("\nSettings:\n");
      sb.append("\t").append(XML_MAX_LEN).append("=").append(maxLen).append("\n");
      sb.append("\t").append(XML_MIN_LEN).append("=").append(minLen).append("\n");
      if (childShield != null) {
        sb.append("\t").append(XML_CHILD_SHIELD).append("=").append(childShield.name).append("\n");
      }
      sb.append("\t").append("regex ").append(XML_MIN_LEN).append("=").append(regexMinLen).append("\n");
      appendMetadataSettings(sb, Metadata.XML_ENDPOINTS, endpointsEnabled, endpointsCaseSensitive);
      appendMetadataSettings(sb, Metadata.XML_PARAMETERS, parameters.enabled, parameters.caseSensitive);
      appendMetadataSettings(sb, Metadata.XML_COOKIES, cookies.enabled, cookies.caseSensitive);
      appendMetadataSettings(sb, Metadata.XML_HEADERS, headers.enabled, headers.caseSensitive);

      sb.append("\nStringRegexes:\n");
      appendRules(sb, rulePatterns);
      appendRules(sb, rulePatternsDetect);

      sb.append("\n").append(XML_REGEX_PATTERNS_CUSTOM).append(":\n");
      appendRules(sb, customRulePatterns);
      appendRules(sb, customRulePatternsDetect);

      if (regexAlways) {
        sb.append("\n\tShield Secured List: *Ignored*");
        sb.append("\n\t").append(XML_REGEX_ALWAYS_REGEX).append("=true (process all parameters)");
        sb.append("\n\tExcept for (exclusion list):\n");
        for (String s : regexAlwaysExclusions) {
          sb.append("\t").append(s);
        }
      }
      sb.append("\n");
      if (!regexAlways) {
        sb.append("Secured Items:\n");
        appendPItemMapToSB(headers.items, sb, "\tHeaders");
        appendPItemMapToSB(cookies.items, sb, "\tCookies");
        appendPItemMapToSB(parameters.items, sb, "\tParameters");
        sb.append("\tEndpoints\n");
        appendEndpoints(endpointParameters, sb);
      }
    }
    logger.info(sb.toString());
  }

  /**
   * Appends formatted rule entries to the log output buffer.
   *
   * @param sb    the string builder to append to
   * @param rules the rules to format
   */
  private static void appendRules(StringBuilder sb, Map<String, Rule> rules) {
    for (Map.Entry<String, Rule> e : rules.entrySet()) {
      sb.append("\t").append(e.getValue().mode).append("\t").append(e.getKey()).append("=").append(e.getValue().pattern).append(FAIL_ON_MATCH).append(e.getValue().failOnMatch).append("\n");
    }
  }

  /**
   * Returns true if the pattern's source contains NO XSS-significant literal
   * character. Always-literal chars ({@code % ; ' " / &}) are checked
   * unconditionally. {@code <} and {@code :} are counted only when the two
   * preceding chars are NOT {@code (?}, which distinguishes literal use from
   * group syntax ({@code (?:...)}, {@code (?<name>...)}, {@code (?<=...)}). Used
   * at load time to decide if char-scan can safely skip this pattern.
   */
  private static boolean patternLacksXssChar(Pattern p) {
    String src = p.pattern();
    for (int i = 0, len = src.length(); i < len; i++) {
      switch (src.charAt(i)) {
      case '%':
      case ';':
      case '\'':
      case '"':
      case '/':
      case '&':
        return false;
      case '<':
      case ':':
        if (i < 2 || src.charAt(i - 2) != '(' || src.charAt(i - 1) != '?')
          return false;
        break;
      default:
        break;
      }
    }
    return true;
  }

  /**
   * Returns {@code true} if the value contains no characters that are
   * significant to XSS attack patterns (e.g., {@code <}, {@code >},
   * {@code %}, quotes, braces). Used as a fast-path to skip regex scanning.
   *
   * @param value the string to inspect
   * @return {@code true} if no XSS-relevant characters are present
   */
  static boolean containsNoXssRelevantChar(String value) {
    int len = value.length();
    for (int i = 0; i < len; i++) {
      switch (value.charAt(i)) {
      case '<':
      case '>':
      case '%':
      case '(':
      case ')':
      case ':':
      case ';':
      case '\'':
      case '"':
      case '/':
      case '\\':
      case '&':
      case '=':
      case '{':
      case '}':
      case 0:
        return false;
      default:
        break;
      }
    }
    return true;
  }

  /**
   * Parses a string as an integer, returning a default value on failure.
   *
   * @param s the string to parse
   * @param d the default value if parsing fails
   * @return the parsed integer, or {@code d} if {@code s} is not a valid integer
   */
  static int parseInt(String s, int d) {
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException nfe) {
      return d;
    }
  }

  /**
   * Parses a string as a double, returning a default value on failure.
   *
   * @param s the string to parse
   * @param d the default value if parsing fails
   * @return the parsed double, or {@code d} if {@code s} is not a valid double
   */
  static double parseDouble(String s, double d) {
    try {
      return Double.parseDouble(s);
    } catch (NumberFormatException nfe) {
      return d;
    }
  }

  /**
   * Appends formatted endpoint information to the log output buffer.
   *
   * @param endpointParameters the endpoint metadata map to format
   * @param sb                 the string builder to append to
   */
  static void appendEndpoints(Map<String, Metadata> endpointParameters, StringBuilder sb) {
    appendItemToSb(sb, endpointParameters);
  }

  /**
   * Appends all items from each metadata entry in the map to the string
   * builder for logging.
   *
   * @param sb  the string builder to append to
   * @param map the endpoint metadata map
   */
  private static void appendItemToSb(StringBuilder sb, Map<String, Metadata> map) {
    for (Map.Entry<String, Metadata> pair : map.entrySet()) {
      appendPItemMapToSB(pair.getValue().items, sb, "\t", pair.getKey()); // "\t" = log indentation prefix
    }
  }

  /**
   * Appends item map entries to the string builder with the given label.
   *
   * @param map   the items to format
   * @param sb    the string builder to append to
   * @param label the section label
   */
  static void appendPItemMapToSB(Map<String, Item> map, StringBuilder sb, String label) {
    appendPItemMapToSB(map, sb, label, "");
  }

  /**
   * Appends item map entries to the string builder with label and suffix.
   *
   * @param map         the items to format
   * @param sb          the string builder to append to
   * @param label       the section label prefix
   * @param labelSuffix additional text appended to the label
   */
  static void appendPItemMapToSB(Map<String, Item> map, StringBuilder sb, String label, String labelSuffix) {
    sb.append(label).append(labelSuffix);
    if (map != null && !map.isEmpty()) {
      for (Map.Entry<String, Item> e : map.entrySet()) {
        sb.append("\n\t\t").append(e.getKey()).append("=").append(e.getValue());
      }
    }
    sb.append("\n");
  }

  /**
   * Appends enabled and case-sensitivity settings for a metadata type to the
   * log output buffer.
   *
   * @param sb            the string builder to append to
   * @param type          the metadata type name (e.g., "parameters")
   * @param enabled       whether the type is enabled
   * @param caseSensitive whether the type uses case-sensitive matching
   */
  private static void appendMetadataSettings(StringBuilder sb, String type, boolean enabled, boolean caseSensitive) {
    sb.append("\t").append(type).append(".").append(XML_ENABLED).append("=").append(enabled).append("\n");
    sb.append("\t").append(type).append(".").append(XML_CASE_SENSITIVE).append("=").append(caseSensitive).append("\n");
  }

  /**
   * Splits a string on the {@value #SEPARATOR} delimiter, discarding empty
   * segments.
   *
   * @param s the string to split (may be {@code null} or empty)
   * @return a list of non-empty segments
   */
  static List<String> split(String s) {
    List<String> out = new ArrayList<>();
    if (s != null && !s.isEmpty()) {
      String[] vs = SEPARATOR_PATTERN.split(s);
      for (String v : vs) {
        if (!v.isEmpty()) {
          out.add(v);
        }
      }
    }
    return out;
  }
}
