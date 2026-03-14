package com.sanwaf.core;

import com.sanwaf.log.Logger;
import com.sanwaf.log.SimpleLogger;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.LinkedHashMap;
import java.util.function.Function;

/**
 * Public API entry point for the Sanwaf web application firewall.
 *
 * <p>Sanwaf inspects {@link jakarta.servlet.ServletRequest} objects for
 * security threats (XSS, SQL injection, etc.) based on rules defined in an
 * XML configuration file. Request parameters, headers, and cookies are
 * validated against one or more {@link Shield} instances, each of which
 * contains a set of {@link Item} rules and string-pattern detectors.</p>
 *
 * <p>Typical usage:</p>
 * <pre>
 *   Sanwaf sanwaf = new Sanwaf(myLogger, "/sanwaf.xml");
 *   if (sanwaf.isThreatDetected(request)) {
 *     // reject the request
 *   }
 * </pre>
 *
 * <p>Configuration is held in an immutable {@link SanwafConfig} snapshot
 * that can be hot-reloaded via {@link #reLoad()}.</p>
 */
public final class Sanwaf {
  static final String DEFAULT_LOGGER_DETECTED_MSG = "NOTE: Sanwaf is using the Default \"SimpleLogger\" logger."
      + " To correct this, implement the com.sanwaf.log.Logger Interface and provide your logger in the Sanwaf constructor.";
  static final String STANDALONE_XML_FILENAME = "sanwaf.xml";
  static final String ATT_LOG_ERROR = "~sanwaf-errors";
  static final String ATT_LOG_DETECT = "~sanwaf-detects";
  static final String ATT_TRANS_ID = "~sanwaf-id";

  private static final int MAX_ITEM_CACHE_SIZE = 64;
  private static final Map<String, Item> itemCache = createLruCache();

  private final String xmlFilename;
  final Logger logger;
  private final Map<String, Item> instanceItemCache = createLruCache();

  volatile SanwafConfig config;

  public enum AllowListType {
    HEADER, COOKIE, PARAMETER
  }

  /**
   * Immutable snapshot of all Sanwaf runtime settings and shields.
   *
   * <p>Created during {@link Sanwaf#loadProperties()} and swapped atomically
   * into {@link Sanwaf#config}. Use {@link #toBuilder()} to produce a
   * mutable copy for reconfiguration.</p>
   */
  static final class SanwafConfig {
    final boolean enabled;
    final boolean verbose;
    final boolean onErrorAddTrackId;
    final boolean onErrorAddParmErrors;
    final boolean onErrorAddParmDetections;
    final boolean onErrorLogParmErrors;
    final boolean onErrorLogParmDetections;
    final boolean onErrorLogParmErrorsVerbose;
    final boolean onErrorLogParmDetectionsVerbose;
    final String securedAppVersion;
    final Shield[] shields;
    final Map<String, Shield> shieldMap;
    final Map<String, String> globalErrorMessages;

    /**
     * Constructs an immutable configuration snapshot.
     *
     * @param enabled                      whether Sanwaf threat detection is active
     * @param verbose                      whether verbose logging is enabled
     * @param onErrorAddTrackId            attach a unique tracking ID to the request on error
     * @param onErrorAddParmErrors         attach blocked-parameter error details to the request
     * @param onErrorAddParmDetections     attach detect-mode parameter details to the request
     * @param onErrorLogParmErrors         log blocked-parameter errors
     * @param onErrorLogParmDetections     log detect-mode parameter findings
     * @param onErrorLogParmErrorsVerbose  log blocked-parameter errors with full detail
     * @param onErrorLogParmDetectionsVerbose log detect-mode findings with full detail
     * @param securedAppVersion            application version string from the config
     * @param shields                      ordered list of configured shields
     * @param shieldMap                    case-insensitive map of shield name to shield
     * @param globalErrorMessages          global error-message overrides keyed by type code
     */
    SanwafConfig(boolean enabled, boolean verbose, boolean onErrorAddTrackId, boolean onErrorAddParmErrors, boolean onErrorAddParmDetections, boolean onErrorLogParmErrors,
        boolean onErrorLogParmDetections, boolean onErrorLogParmErrorsVerbose, boolean onErrorLogParmDetectionsVerbose, String securedAppVersion, List<Shield> shields, Map<String, Shield> shieldMap,
        Map<String, String> globalErrorMessages) {
      this.enabled = enabled;
      this.verbose = verbose;
      this.onErrorAddTrackId = onErrorAddTrackId;
      this.onErrorAddParmErrors = onErrorAddParmErrors;
      this.onErrorAddParmDetections = onErrorAddParmDetections;
      this.onErrorLogParmErrors = onErrorLogParmErrors;
      this.onErrorLogParmDetections = onErrorLogParmDetections;
      this.onErrorLogParmErrorsVerbose = onErrorLogParmErrorsVerbose;
      this.onErrorLogParmDetectionsVerbose = onErrorLogParmDetectionsVerbose;
      this.securedAppVersion = securedAppVersion;
      this.shields = shields.toArray(new Shield[0]);
      this.shieldMap = Collections.unmodifiableMap(shieldMap);
      this.globalErrorMessages = Collections.unmodifiableMap(globalErrorMessages);
    }

    /**
     * Creates a mutable {@link Builder} pre-populated with this config's values.
     *
     * @return a new builder seeded from this snapshot
     */
    Builder toBuilder() {
      return new Builder(this);
    }

    /**
     * Mutable builder for {@link SanwafConfig}.
     *
     * <p>Obtained via {@link SanwafConfig#toBuilder()} and finalized with
     * {@link #build()}. Each setter returns {@code this} for chaining.</p>
     */
    static final class Builder {
      private boolean enabled;
      private boolean verbose;
      private boolean onErrorAddTrackId;
      private boolean onErrorAddParmErrors;
      private boolean onErrorAddParmDetections;
      private boolean onErrorLogParmErrors;
      private boolean onErrorLogParmDetections;
      private boolean onErrorLogParmErrorsVerbose;
      private boolean onErrorLogParmDetectionsVerbose;
      private final String securedAppVersion;
      private final List<Shield> shields;
      private final Map<String, Shield> shieldMap;
      private final Map<String, String> globalErrorMessages;

      /**
       * Creates a builder pre-populated from the given config.
       *
       * @param c the configuration to copy
       */
      Builder(SanwafConfig c) {
        this.enabled = c.enabled;
        this.verbose = c.verbose;
        this.onErrorAddTrackId = c.onErrorAddTrackId;
        this.onErrorAddParmErrors = c.onErrorAddParmErrors;
        this.onErrorAddParmDetections = c.onErrorAddParmDetections;
        this.onErrorLogParmErrors = c.onErrorLogParmErrors;
        this.onErrorLogParmDetections = c.onErrorLogParmDetections;
        this.onErrorLogParmErrorsVerbose = c.onErrorLogParmErrorsVerbose;
        this.onErrorLogParmDetectionsVerbose = c.onErrorLogParmDetectionsVerbose;
        this.securedAppVersion = c.securedAppVersion;
        this.shields = Arrays.asList(c.shields);
        this.shieldMap = c.shieldMap;
        this.globalErrorMessages = c.globalErrorMessages;
      }

      /**
       * Sets the enabled flag.
       *
       * @param v {@code true} to enable threat detection
       * @return this builder
       */
      Builder enabled(boolean v) {
        this.enabled = v;
        return this;
      }

      /**
       * Sets the verbose-logging flag.
       *
       * @param v {@code true} for verbose output
       * @return this builder
       */
      Builder verbose(boolean v) {
        this.verbose = v;
        return this;
      }

      /**
       * Sets whether a tracking ID is attached to the request on error.
       *
       * @param v {@code true} to attach a tracking ID
       * @return this builder
       */
      Builder onErrorAddTrackId(boolean v) {
        this.onErrorAddTrackId = v;
        return this;
      }

      /**
       * Sets whether blocked-parameter errors are added as request attributes.
       *
       * @param v {@code true} to add error attributes
       * @return this builder
       */
      Builder onErrorAddParmErrors(boolean v) {
        this.onErrorAddParmErrors = v;
        return this;
      }

      /**
       * Sets whether detect-mode findings are added as request attributes.
       *
       * @param v {@code true} to add detection attributes
       * @return this builder
       */
      Builder onErrorAddParmDetections(boolean v) {
        this.onErrorAddParmDetections = v;
        return this;
      }

      /**
       * Sets whether blocked-parameter errors are logged.
       *
       * @param v {@code true} to log errors
       * @return this builder
       */
      Builder onErrorLogParmErrors(boolean v) {
        this.onErrorLogParmErrors = v;
        return this;
      }

      /**
       * Sets whether detect-mode findings are logged.
       *
       * @param v {@code true} to log detections
       * @return this builder
       */
      Builder onErrorLogParmDetections(boolean v) {
        this.onErrorLogParmDetections = v;
        return this;
      }

      /**
       * Sets whether blocked-parameter errors are logged with full detail.
       *
       * @param v {@code true} for verbose error logging
       * @return this builder
       */
      Builder onErrorLogParmErrorsVerbose(boolean v) {
        this.onErrorLogParmErrorsVerbose = v;
        return this;
      }

      /**
       * Sets whether detect-mode findings are logged with full detail.
       *
       * @param v {@code true} for verbose detection logging
       * @return this builder
       */
      Builder onErrorLogParmDetectionsVerbose(boolean v) {
        this.onErrorLogParmDetectionsVerbose = v;
        return this;
      }

      /**
       * Builds an immutable {@link SanwafConfig} from this builder's state.
       *
       * @return a new configuration snapshot
       */
      SanwafConfig build() {
        return new SanwafConfig(enabled, verbose, onErrorAddTrackId, onErrorAddParmErrors, onErrorAddParmDetections, onErrorLogParmErrors, onErrorLogParmDetections, onErrorLogParmErrorsVerbose,
            onErrorLogParmDetectionsVerbose, securedAppVersion, shields, shieldMap, globalErrorMessages);
      }
    }
  }

  /**
   * Creates a Sanwaf instance with the default {@link SimpleLogger} and
   * the default XML configuration file ({@code sanwaf.xml} on the classpath).
   *
   * <p>The {@link SimpleLogger} is not intended for production use.
   *
   * @throws IOException if the configuration file cannot be read
   */
  public Sanwaf() throws IOException {
    this(new SimpleLogger(), "/" + STANDALONE_XML_FILENAME);
    logger.info(DEFAULT_LOGGER_DETECTED_MSG);
  }

  /**
   * Creates a Sanwaf instance with the given logger and the default XML
   * configuration file ({@code sanwaf.xml} on the classpath).
   *
   * @param logger a {@link Logger} implementation to use for all Sanwaf logging
   * @throws IOException if the configuration file cannot be read
   */
  public Sanwaf(Logger logger) throws IOException {
    this(logger, "/" + STANDALONE_XML_FILENAME);
  }

  /**
   * Creates a Sanwaf instance with the given logger and XML configuration file.
   *
   * @param logger   a {@link Logger} implementation to use for all Sanwaf logging
   * @param filename classpath-relative path to a valid Sanwaf XML configuration file
   * @throws IOException if the configuration file cannot be read
   */
  public Sanwaf(Logger logger, String filename) throws IOException {
    this.logger = logger;
    this.xmlFilename = filename;
    loadProperties();
  }

  /**
   * Scans the request against all configured shields, stopping at the first
   * detected threat. Error attributes are added to the request when
   * {@code provideTrackId} or {@code provideErrors} are enabled in the XML
   * configuration.
   *
   * @param req the servlet request to scan
   * @return {@code true} if a threat is detected
   * @see #getTrackingId(HttpServletRequest)
   * @see #getErrors(HttpServletRequest)
   */
  public boolean isThreatDetected(ServletRequest req) {
    return isThreatDetected(req, false, false);
  }

  /**
   * Scans the request against all configured shields with logging control.
   *
   * @param req the servlet request to scan
   * @param log {@code true} to log detected threats
   * @return {@code true} if a threat is detected
   * @deprecated Use {@link #isThreatDetected(ServletRequest, boolean, boolean)} instead.
   *             The single boolean is ambiguous — callers often intend {@code doAllBlocks}
   *             but this parameter controls {@code log}.
   */
  @Deprecated
  public boolean isThreatDetected(ServletRequest req, boolean log) {
    return isThreatDetected(req, null, false, log);
  }

  /**
   * Tests whether any configured shield detects a threat in the request.
   *
   * @param req         the servlet request to scan
   * @param doAllBlocks {@code true} to evaluate all block-mode items rather
   *                    than stopping at the first failure
   * @param log         {@code true} to log detected threats
   * @return {@code true} if at least one threat is detected
   */
  public boolean isThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log) {
    return isThreatDetected(req, null, doAllBlocks, log);
  }

  /**
   * Scans the request against the specified shields without logging.
   *
   * @param req         the servlet request to scan
   * @param shieldList  shield names to evaluate, or {@code null} for all shields
   * @param doAllBlocks {@code true} to evaluate every block-mode item rather than
   *                    stopping at the first failure
   * @return {@code true} if at least one threat is detected
   * @see #getTrackingId(HttpServletRequest)
   * @see #getErrors(HttpServletRequest)
   */
  public boolean isThreatDetected(ServletRequest req, List<String> shieldList, boolean doAllBlocks) {
    return isThreatDetected(req, shieldList, doAllBlocks, false);
  }

  /**
   * Scans the request against the specified shields with full control over
   * block evaluation and logging.
   *
   * <p>When a threat is detected and the XML configuration enables it,
   * error attributes are added to the request for later retrieval via
   * {@link #getTrackingId(HttpServletRequest)} and {@link #getErrors(HttpServletRequest)}.
   *
   * @param req         the servlet request to scan
   * @param shieldList  shield names to evaluate, or {@code null} for all shields
   * @param doAllBlocks {@code true} to evaluate every block-mode item rather than
   *                    stopping at the first failure
   * @param log         {@code true} to log detected threats
   * @return {@code true} if at least one threat is detected
   */
  public boolean isThreatDetected(ServletRequest req, List<String> shieldList, boolean doAllBlocks, boolean log) {
    SanwafConfig cfg = this.config;
    if (!cfg.enabled || !(req instanceof HttpServletRequest)) {
      return false;
    }
    boolean threat = false;
    Shield[] shields = cfg.shields;
    for (Shield sh : shields) {
      if ((shieldList == null || shieldList.contains(sh.name)) && sh.threatDetected(req, doAllBlocks, log)) {
        if (!doAllBlocks) {
          return true;
        }
        threat = true;
      }
    }
    return threat;
  }

  /**
   * Tests whether the given value is a threat according to any configured shield's
   * string patterns. No request attributes are set.
   *
   * @param value the string to scan
   * @return {@code true} if a threat is detected
   */
  public boolean isThreat(String value) {
    return checkValueForShieldThreats(value, null, null);
  }

  /**
   * Tests whether the given value is a threat using an inline XML item definition.
   * The parsed item is cached for subsequent calls with the same XML.
   *
   * @param value the string to scan
   * @param sXml  inline XML conforming to the Sanwaf item schema
   * @return {@code true} if the value fails validation
   */
  public static boolean isThreatByXml(String value, String sXml) {
    Item item;
    synchronized (itemCache) {
      item = cachedParseItem(itemCache, sXml, xml -> ItemFactory.parseItem(null, new Xml(xml), false, null));
    }
    return item.inError(null, null, value, false, false);
  }

  /**
   * Tests whether the given value is a threat using an inline XML item definition.
   *
   * @param value the string to scan
   * @param sXml  inline XML conforming to the Sanwaf item schema
   * @return {@code true} if the value fails validation
   * @deprecated Use {@link #isThreatByXml(String, String)} instead. This static overload
   *             is easily confused with the instance method {@link #isThreat(String, String, ServletRequest)}.
   */
  @Deprecated
  public static boolean isThreat(String value, String sXml) {
    return isThreatByXml(value, sXml);
  }

  /**
   * Tests whether the given value is a threat using the named shield's string
   * patterns. Error attributes are added to the request when configured.
   *
   * @param value      the string to scan
   * @param shieldName the shield whose string patterns to apply
   * @param req        the servlet request for attribute storage (may be {@code null})
   * @return {@code true} if a threat is detected
   * @see #getTrackingId(HttpServletRequest)
   * @see #getErrors(HttpServletRequest)
   */
  public boolean isThreat(String value, String shieldName, ServletRequest req) {
    return checkValueForShieldThreats(value, shieldName, req);
  }

  /**
   * Tests whether the given value is a threat using an inline XML item definition
   * evaluated within the context of the named shield. The shield's string patterns
   * are applied for {@code String} types, and its regex rules for {@code Regex} types.
   * Error attributes are added to the request when configured.
   *
   * @param value      the string to scan
   * @param shieldName the shield whose patterns/context to use
   * @param req        the servlet request for URI testing and attribute storage
   * @param xml        inline XML conforming to the Sanwaf item schema
   * @return {@code true} if the value fails validation
   * @see #getTrackingId(HttpServletRequest)
   * @see #getErrors(HttpServletRequest)
   */
  public boolean isThreat(String value, String shieldName, ServletRequest req, String xml) {
    SanwafConfig cfg = this.config;
    Item item;
    synchronized (instanceItemCache) {
      item = cachedParseItem(instanceItemCache, xml, x -> ItemFactory.parseItem(new Xml(x), logger));
    }
    Shield sh = (shieldName != null) ? cfg.shieldMap.get(shieldName) : null;
    if (sh == null) {
      if (logger.isErrorEnabled()) {
        logger.error("Invalid ShieldName provided to isThreat():" + shieldName);
      }
      return false;
    }
    boolean result = item.inError(req, sh, value, false, false);
    if (result && req != null && cfg.onErrorAddTrackId && req.getAttribute(ATT_TRANS_ID) == null) {
      req.setAttribute(ATT_TRANS_ID, UUID.randomUUID().toString());
    }
    return result;
  }

  /**
   * Tests whether the given value is a threat using the named shield's string
   * patterns, without logging. Delegates to
   * {@link #checkValueForShieldThreats(String, String, ServletRequest, boolean)}.
   *
   * @param value      the string to scan
   * @param shieldName the shield name, or {@code null} to check all shields
   * @param req        the servlet request (may be {@code null})
   * @return {@code true} if a threat is detected
   */
  public boolean checkValueForShieldThreats(String value, String shieldName, ServletRequest req) {
    return checkValueForShieldThreats(value, shieldName, req, false);
  }

  /**
   * Tests whether the given value is a threat using the named shield's string
   * patterns, with optional logging.
   *
   * @param value      the string to scan
   * @param shieldName the shield name, or {@code null} to check all shields
   * @param req        the servlet request (may be {@code null})
   * @param log        {@code true} to log detected threats
   * @return {@code true} if a threat is detected
   */
  public boolean checkValueForShieldThreats(String value, String shieldName, ServletRequest req, boolean log) {
    SanwafConfig cfg = this.config;
    Shield[] shields = cfg.shields;
    for (Shield sh : shields) {
      if ((shieldName == null || shieldName.equals(sh.name)) && sh.threat(req, value, log)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Retrieves the value of an allow-listed header, cookie, or parameter.
   * The value is returned only if the name appears in a shield's
   * {@code <metadata><secured>} configuration block.
   *
   * @param name the header, cookie, or parameter name
   * @param type the category to look up ({@link AllowListType#HEADER},
   *             {@link AllowListType#COOKIE}, or {@link AllowListType#PARAMETER})
   * @param req  the request to extract the value from
   * @return the value, or {@code null} if the name is not allow-listed
   */
  public String getAllowListedValue(String name, AllowListType type, HttpServletRequest req) {
    SanwafConfig cfg = this.config;
    Shield[] shields = cfg.shields;
    for (Shield sh : shields) {
      String value = sh.getAllowListedValue(name, type, req);
      if (value != null) {
        return value;
      }
    }
    return null;
  }

  /**
   * Reloads the Sanwaf configuration from the XML file, clearing all cached items.
   *
   * @throws IOException if the configuration file cannot be read
   */
  public void reLoad() throws IOException {
    instanceItemCache.clear();
    loadProperties();
  }

  /**
   * Returns the tracking ID assigned to the request when a threat was detected.
   * Useful for correlating user-facing error messages with log entries.
   *
   * @param req the request that was scanned by {@link #isThreatDetected(ServletRequest)}
   * @return the tracking ID, or {@code null} if none was assigned
   */
  public static String getTrackingId(HttpServletRequest req) {
    Object o = req.getAttribute(ATT_TRANS_ID);
    if (o != null) {
      return String.valueOf(o);
    }
    return null;
  }

  /**
   * Returns the blocked-threat errors from the request as a JSON array string.
   * Only contains the first error found during {@link #isThreatDetected(ServletRequest)};
   * use {@link #rescanAndGetAllErrors(HttpServletRequest)} to collect all errors.
   *
   * @param req the request that was scanned
   * @return a JSON array string of errors, or {@code null} if none
   */
  public static String getErrors(HttpServletRequest req) {
    return formatAttributeList(req.getAttribute(ATT_LOG_ERROR));
  }

  /**
   * Clears existing error attributes, re-scans every parameter/header/cookie
   * with {@code doAllBlocks=true}, and returns all detected threats as a JSON
   * array string.
   *
   * @param req the request to re-scan
   * @return a JSON array string of all errors, or {@code null} if none
   */
  public String rescanAndGetAllErrors(HttpServletRequest req) {
    if (req == null) {
      return null;
    }
    SanwafConfig cfg = this.config;
    if (cfg.onErrorAddParmErrors) {
      // clear out the one from the block
      req.setAttribute(ATT_LOG_ERROR, null);
    }
    // call all blocks, don't worry about the detects as they will have already been
    // processed.
    isThreatDetected(req, null, true);
    return formatAttributeList(req.getAttribute(ATT_LOG_ERROR));
  }

  /**
   * Re-scans the request and returns all errors as a JSON array string.
   *
   * @param req the request to re-scan
   * @return a JSON array string of all errors, or {@code null} if none
   * @deprecated Renamed to {@link #rescanAndGetAllErrors(HttpServletRequest)} to make
   *             the re-scan side-effect explicit.
   */
  @Deprecated
  public String getAllErrors(HttpServletRequest req) {
    return rescanAndGetAllErrors(req);
  }

  /**
   * Returns detected-but-not-blocked threats from the request as a JSON array
   * string. These are items configured in detect mode rather than block mode.
   *
   * @param req the request that was scanned
   * @return a JSON array string of detections, or {@code null} if none
   */
  public static String getDetects(HttpServletRequest req) {
    return formatAttributeList(req.getAttribute(ATT_LOG_DETECT));
  }

  /**
   * Formats a request-attribute value (expected to be a {@code Collection<String>})
   * as a JSON array string.
   *
   * @param o the attribute value, typically a {@code Collection<String>}
   * @return a JSON array string, or {@code null} if the collection is absent or empty
   */
  @SuppressWarnings("unchecked")
  private static String formatAttributeList(Object o) {
    if (o instanceof Collection) {
      Collection<String> list = (Collection<String>) o;
      if (list.isEmpty()) {
        return null;
      }
      return "[" + String.join(",", list) + "]";
    }
    return null;
  }

  /**
   * Looks up a shield by name (case-insensitive).
   *
   * @param name the shield name, or {@code null}
   * @return the matching {@link Shield}, or {@code null} if not found
   */
  Shield getShield(String name) {
    if (name == null) {
      return null;
    }
    return config.shieldMap.get(name);
  }

  /**
   * Creates a synchronized LRU cache backed by a {@link LinkedHashMap}
   * with a maximum size of {@link #MAX_ITEM_CACHE_SIZE}.
   *
   * @param <K> the key type
   * @param <V> the value type
   * @return a new thread-safe LRU map
   */
  private static <K, V> Map<K, V> createLruCache() {
    return Collections.synchronizedMap(new LinkedHashMap<K, V>(MAX_ITEM_CACHE_SIZE, 0.75f, true) {
      @Override
      protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
        return size() > MAX_ITEM_CACHE_SIZE;
      }
    });
  }

  /**
   * Returns a cached {@link Item} for the given XML, parsing it on first access.
   *
   * @param cache  the LRU cache to consult
   * @param xml    the XML string used as both cache key and parser input
   * @param parser a function that parses the XML into an {@link Item}
   * @return the cached or newly parsed item
   */
  private static Item cachedParseItem(Map<String, Item> cache, String xml, Function<String, Item> parser) {
    return cache.computeIfAbsent(xml, parser);
  }

  // XML LOAD CODE
  private static final String XML_GLOBAL_SETTINGS = "global-settings";
  private static final String XML_ENABLED = "enabled";
  private static final String XML_VERBOSE = "verbose";
  private static final String XML_APP_VER = "app.version";
  private static final String XML_ERR_HANDLING = "errorHandling";
  private static final String XML_ERR_SET_ATT_TRACK_ID = "provideTrackId";
  private static final String XML_SET_ATT_PARM_ERR = "provideErrors";
  private static final String XML_SET_ATT_PARM_DETECT = "provideDetects";
  private static final String XML_LOG_PARM_ERR = "logErrors";
  private static final String XML_LOG_PARM_DETECT = "logDetects";
  private static final String XML_LOG_PARM_ERR_VERB = "logErrorsVerbose";
  private static final String XML_LOG_PARM_DETECT_VERB = "logDetectsVerbose";
  private static final String XML_SHIELD = "shield";

  /**
   * Parses the XML configuration file and atomically replaces {@link #config}
   * with a new {@link SanwafConfig} snapshot. Called during construction and
   * from {@link #reLoad()}.
   *
   * @throws IOException if the configuration file cannot be read or parsed
   */
  private synchronized void loadProperties() throws IOException {
    long start = System.currentTimeMillis();
    Xml xml;
    try {
      xml = new Xml(Sanwaf.class.getResource(xmlFilename));
    } catch (IOException e) {
      throw new IOException("Sanwaf Failed to load config file " + xmlFilename + ".  \n**Server is NOT protected**\n", e);
    }

    String settingsBlock = xml.get(XML_GLOBAL_SETTINGS);
    Xml settingsBlockXml = new Xml(settingsBlock);
    boolean enabled = Boolean.parseBoolean(settingsBlockXml.get(XML_ENABLED));
    boolean verbose = Boolean.parseBoolean(settingsBlockXml.get(XML_VERBOSE));
    String securedAppVersion = settingsBlockXml.get(XML_APP_VER);
    if (logger.isInfoEnabled()) {
      logger.info("Starting Sanwaf:");
      logger.info("\n\tenabled=" + enabled + "\n\t" + XML_VERBOSE + "=" + verbose + "\n\t" + XML_APP_VER + "=" + securedAppVersion);
    }

    String errorBlock = xml.get(XML_ERR_HANDLING);
    Xml errorBlockXml = new Xml(errorBlock);
    boolean onErrorAddTrackId = Boolean.parseBoolean(errorBlockXml.get(XML_ERR_SET_ATT_TRACK_ID));
    boolean onErrorAddParmErrors = Boolean.parseBoolean(errorBlockXml.get(XML_SET_ATT_PARM_ERR));
    boolean onErrorAddParmDetections = Boolean.parseBoolean(errorBlockXml.get(XML_SET_ATT_PARM_DETECT));
    boolean onErrorLogParmErrors = Boolean.parseBoolean(errorBlockXml.get(XML_LOG_PARM_ERR));
    boolean onErrorLogParmDetections = Boolean.parseBoolean(errorBlockXml.get(XML_LOG_PARM_DETECT));
    boolean onErrorLogParmErrorsVerbose = Boolean.parseBoolean(errorBlockXml.get(XML_LOG_PARM_ERR_VERB));
    boolean onErrorLogParmDetectionsVerbose = Boolean.parseBoolean(errorBlockXml.get(XML_LOG_PARM_DETECT_VERB));

    Map<String, String> globalErrorMessages = new HashMap<>(22); // 16 entries; (16/0.75)+1 avoids resize
    ItemFactory.setErrorMessages(globalErrorMessages, xml);
    if (logger.isInfoEnabled()) {
      logger.info("\tAddTrackId=" + onErrorAddTrackId + "\n\tAddErrors=" + onErrorAddParmErrors + "\n\tLogErrors=" + onErrorLogParmErrors + "\n\tLogErrorsVerbose=" + onErrorLogParmErrorsVerbose
          + "\n\tAddDetections=" + onErrorAddParmDetections + "\n\tLogDetects=" + onErrorLogParmDetections + "\n\tLogDetectsVerbose=" + onErrorLogParmDetectionsVerbose);
    }

    List<Shield> shields = new ArrayList<>();
    Map<String, Shield> shieldMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    String[] shieldXMLs = xml.getAll(XML_SHIELD);
    for (String item : shieldXMLs) {
      Shield sh = new Shield(this, xml, new Xml(item), logger, verbose);
      shields.add(sh);
      shieldMap.put(sh.name, sh);
    }

    this.config = new SanwafConfig(enabled, verbose, onErrorAddTrackId, onErrorAddParmErrors, onErrorAddParmDetections, onErrorLogParmErrors, onErrorLogParmDetections, onErrorLogParmErrorsVerbose,
        onErrorLogParmDetectionsVerbose, securedAppVersion, shields, shieldMap, globalErrorMessages);
    warnOnSuspiciousDefaults(this.config, settingsBlock, errorBlock);

    if (logger.isInfoEnabled()) {
      logger.info("Started in: " + (System.currentTimeMillis() - start) + " ms.");
    }
  }

  /**
   * Logs warnings when the loaded configuration contains defaults that are
   * likely unintentional (e.g., disabled, no shields, silent error handling).
   *
   * @param cfg           the newly loaded configuration
   * @param settingsBlock raw XML content of the global-settings element
   * @param errorBlock    raw XML content of the errorHandling element
   */
  private void warnOnSuspiciousDefaults(SanwafConfig cfg, String settingsBlock, String errorBlock) {
    if (!logger.isWarnEnabled()) {
      return;
    }
    if (!cfg.enabled) {
      logger.warn("Sanwaf is DISABLED (enabled=false). If unintentional, check <global-settings><enabled>");
    }
    if (settingsBlock.isEmpty()) {
      logger.warn("<global-settings> block is missing from config");
    }
    if (errorBlock.isEmpty()) {
      logger.warn("<errorHandling> block is missing from config");
    }
    if (cfg.shields.length == 0) {
      logger.warn("No shields configured — nothing will be validated");
    }
    if (!cfg.onErrorAddParmErrors && !cfg.onErrorLogParmErrors) {
      logger.warn("Error reporting is disabled (provideErrors=false, logErrors=false) — blocked threats will be silent");
    }
  }

}
