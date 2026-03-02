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

public final class Sanwaf
{
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

  public enum AllowListType
  {
    HEADER, COOKIE, PARAMETER
  }

  static final class SanwafConfig
  {
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

    SanwafConfig(boolean enabled, boolean verbose, boolean onErrorAddTrackId,
        boolean onErrorAddParmErrors, boolean onErrorAddParmDetections,
        boolean onErrorLogParmErrors, boolean onErrorLogParmDetections,
        boolean onErrorLogParmErrorsVerbose, boolean onErrorLogParmDetectionsVerbose,
        String securedAppVersion, List<Shield> shields, Map<String, Shield> shieldMap,
        Map<String, String> globalErrorMessages)
    {
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

    Builder toBuilder()
    {
      return new Builder(this);
    }

    static final class Builder
    {
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

      Builder(SanwafConfig c)
      {
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

      Builder enabled(boolean v) { this.enabled = v; return this; }
      Builder verbose(boolean v) { this.verbose = v; return this; }
      Builder onErrorAddTrackId(boolean v) { this.onErrorAddTrackId = v; return this; }
      Builder onErrorAddParmErrors(boolean v) { this.onErrorAddParmErrors = v; return this; }
      Builder onErrorAddParmDetections(boolean v) { this.onErrorAddParmDetections = v; return this; }
      Builder onErrorLogParmErrors(boolean v) { this.onErrorLogParmErrors = v; return this; }
      Builder onErrorLogParmDetections(boolean v) { this.onErrorLogParmDetections = v; return this; }
      Builder onErrorLogParmErrorsVerbose(boolean v) { this.onErrorLogParmErrorsVerbose = v; return this; }
      Builder onErrorLogParmDetectionsVerbose(boolean v) { this.onErrorLogParmDetectionsVerbose = v; return this; }

      SanwafConfig build()
      {
        return new SanwafConfig(enabled, verbose, onErrorAddTrackId, onErrorAddParmErrors,
            onErrorAddParmDetections, onErrorLogParmErrors, onErrorLogParmDetections,
            onErrorLogParmErrorsVerbose, onErrorLogParmDetectionsVerbose, securedAppVersion,
            shields, shieldMap, globalErrorMessages);
      }
    }
  }

  /**
   * Default Sanwaf constructor.
   *
   * <pre>
   * Creates an instance of Sanwaf initializing it with:
   *  -default java.util.logging.Logger (com.sanwaf.log.SimpleLogger)
   *   should not be used in a production environment
   *  -default Sanwaf XML configuration file (sanwaf.xml on classpath)
   * </pre>
   *
   */
  public Sanwaf() throws IOException
  {
    this(new SimpleLogger(), "/" + STANDALONE_XML_FILENAME);
    logger.info(DEFAULT_LOGGER_DETECTED_MSG);
  }

  /**
   * Sanwaf constructor.
   *
   * <pre>
   * Creates a new Sanwaf instance initializing it with the logger provided; 
   * Uses the default Sanwaf XML configuration file (sanwaf.xml on classpath)
   * </pre>
   *
   * @param logger
   *          A logger of your choice that implements the com.sanwaf.log.Logger
   *          interface
   */
  public Sanwaf(Logger logger) throws IOException
  {
    this(logger, "/" + STANDALONE_XML_FILENAME);
  }

  /**
   * Sanwaf constructor where you specify the logger and properties file to use
   *
   * <pre>
   * Creates a new instance of Sanwaf using the logger & Sanwaf XML configuration provided.
   * </pre>
   *
   * @param logger
   *          A logger of your choice that implements the com.sanwaf.log.Logger
   *          interface
   * @param filename
   *          Fully qualified path to a valid Sanwaf XML file
   */
  public Sanwaf(Logger logger, String filename) throws IOException
  {
    this.logger = logger;
    this.xmlFilename = filename;
    loadProperties();
  }

  /**
   * Test if a threat is detected in a given request
   *
   * <pre>
   * Threats detected are derived from all shields configurations
   * If an error is detected, attributes will be added to request for processing latter.  
   *  Attributes added are dependent on the properties settings of:
   *        <provideTrackId>true/false</provideTrackId>
   *        <provideErrors>true/false</provideErrors>
   * Use the following methods in this class to retrieve the values:
   *  public static String getTrackingId(HttpServletRequest req)
   *  public static String getErrors(HttpServletRequest req)
   * </pre>
   *
   * @param req
   *          ServletRequest the ServletRequest object you want to scan for
   *          threats
   * @return boolean true/false if a threat was detected
   */
  public boolean isThreatDetected(ServletRequest req)
  {
    return isThreatDetected(req, false, false);
  }

  /**
   * @deprecated Ambiguous boolean parameter — the {@code log} parameter is easily
   *             mistaken for {@code doAllBlocks}. A call like
   *             {@code isThreatDetected(req, true)} sets {@code log=true, doAllBlocks=false},
   *             which is the opposite of the likely intent.
   *             Use {@link #isThreatDetected(ServletRequest, boolean, boolean)} instead.
   */
  @Deprecated
  public boolean isThreatDetected(ServletRequest req, boolean log)
  {
    return isThreatDetected(req, null, false, log);
  }

  public boolean isThreatDetected(ServletRequest req, boolean doAllBlocks, boolean log)
  {
    return isThreatDetected(req, null, doAllBlocks, log);
  }

  /**
   * Test if a threat is detected in a given request for a provided list of
   * Shields
   *
   * <pre>
   * Threats detected are derived from all shields configurations
   * If an error is detected, attributes will be added to request for processing latter.  
   *  Attributes added are dependent on the properties settings of:
   *        <provideTrackId>true/false</provideTrackId>
   *        <provideErrors>true/false</provideErrors>
   * Use the following methods in this class to retrieve the values:
   *  public static String getTrackingId(HttpServletRequest req)
   *  public static String getErrors(HttpServletRequest req)
   * </pre>
   *
   * @param req
   *          ServletRequest the ServletRequest object you want to scan for
   *          threats
   * @param shieldList
   *          list of string shield names you want run against
   * @param doAllBlocks
   *          flag to control if sanwaf will stop on the first item marked as Block.  Set to true to run all blocks.
   *          this is used with you want to get all the errors for a given request, otherwise, only the first block will be reported. 
   * @return boolean true/false if a threat was detected
   */
  public boolean isThreatDetected(ServletRequest req, List<String> shieldList, boolean doAllBlocks)
  {
    return isThreatDetected(req, shieldList, doAllBlocks, false);
  }

  /**
   * Test if a threat is detected in a given request for a provided list of
   * Shields
   *
   * <pre>
   * Threats detected are derived from all shields configurations
   * If an error is detected, attributes will be added to request for processing latter.  
   *  Attributes added are dependent on the properties settings of:
   *        <provideTrackId>true/false</provideTrackId>
   *        <provideErrors>true/false</provideErrors>
   * Use the following methods in this class to retrieve the values:
   *  public static String getTrackingId(HttpServletRequest req)
   *  public static String getErrors(HttpServletRequest req)
   * </pre>
   *
   * @param req
   *          ServletRequest the ServletRequest object you want to scan for
   *          threats
   * @param shieldList
   *          list of string shield names you want run against
   * @param doAllBlocks
   *          flag to control if sanwaf will stop on the first item marked as Block.  Set to true to run all blocks.
   *          this is used with you want to get all the errors for a given request, otherwise, only the first block will be reported. 
   * @param log
   * 		  flag to control if sanwaf will log errors detected. you can use the getAllErrors method to pull errors from the request object
   * @return boolean true/false if a threat was detected
   */
  public boolean isThreatDetected(ServletRequest req, List<String> shieldList, boolean doAllBlocks, boolean log)
  {
    SanwafConfig cfg = this.config;
    if (!cfg.enabled || !(req instanceof HttpServletRequest))
    {
      return false;
    }
    boolean threat = false;
    Shield[] shields = cfg.shields;
    for (Shield sh : shields)
    {
      if ((shieldList == null || shieldList.contains(sh.name)) && sh.threatDetected(req, doAllBlocks, log))
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

  /**
   * Test if a threat is detected in a value
   *
   * <pre>
   * Threats detected are derived from all shields configurations
   * No error attributes are set.
   * </pre>
   *
   * @param value
   *          the string you want to scan for threats
   * @return boolean true/false if a threat was detected
   */
  public boolean isThreat(String value)
  {
    return checkValueForShieldThreats(value, null, null);
  }

  /**
   * Test if a threat is detected in a value using a given XML Configuration
   * provided
   *
   * <pre>
   * configure sanwaf with XML inline for validations
   * </pre>
   *
   * @param value
   *          the string you want to scan for threats
   * @param sXml
   *          item XML to be used to validate with
   * @return boolean true/false if a threat was detected
   */
  public static boolean isThreatByXml(String value, String sXml)
  {
    Item item = cachedParseItem(itemCache, sXml,
        xml -> ItemFactory.parseItem(null, new Xml(xml), false, null));
    return item.inError(null, null, value, false, false);
  }

  /**
   * @deprecated Ambiguous overload — a caller writing {@code sanwaf.isThreat(value, someString)}
   *             hits this static method (no shield context) instead of the instance overloads.
   *             Use {@link #isThreatByXml(String, String)} instead.
   */
  @Deprecated
  public static boolean isThreat(String value, String sXml)
  {
    return isThreatByXml(value, sXml);
  }

  /**
   * Test if a threat is detected in a value using a given shield
   *
   * <pre>
   * Threats detected are derived from the provided shield's configuration
   * The shields stringPatterns will be executed against the value
   * Error attributes will be set if specified
   * When an error is detected, attributes will be added to request for processing latter.
   *  Attributes added are dependent on the properties settings of:
   *        <provideTrackId>true/false</provideTrackId>
   *        <provideErrors>true/false</provideErrors>
   * Use the following methods in this class to retrieve the values:
   *  public static String getTrackingId(HttpServletRequest req)
   *  public static String getErrors(HttpServletRequest req)
   * </pre>
   *
   * @param value
   *          the string you want to scan for threats
   * @param shieldName
   *          The shields name that you want to execute the stringPatterns from
   * @param req
   *          ServletRequest to add the error attributes
   * @return boolean true/false if a threat was detected
   */
  public boolean isThreat(String value, String shieldName, ServletRequest req)
  {
    return checkValueForShieldThreats(value, shieldName, req);
  }

  /**
   * Test if a threat is detected in a value using XML provided
   *
   * <pre>
   * Threats detected are derived from the XML provided
   * XML must conform to Sanwaf.xml specifications
   * The specified shield's stringPatterns will be executed against the value for datatype String
   * Error attributes will be set if specified
   * When an error is detected, attributes will be added to request for processing latter.
   *  Attributes added are dependent on the properties settings of:
   *        <provideTrackId>true/false</provideTrackId>
   *        <provideErrors>true/false</provideErrors>
   * Use the following methods in this class to retrieve the values:
   *  public static String getTrackingId(HttpServletRequest req)
   *  public static String getErrors(HttpServletRequest req)
   * </pre>
   *
   * @param value
   *          the string you want to scan for threats
   * @param shieldName
   *          the shields name that you want to execute the stringPatterns from
   *          (String data type only) or use the custom regex's specified (regex
   *          data type only)
   * @param req
   *          calling ServletRequest object used to test URIs
   * @param xml
   *          XML String to configure the data type. See sanwaf.xml
   *          shield/metadata/secured section for configuration details
   * @return boolean true/false if a threat was detected
   */
  public boolean isThreat(String value, String shieldName, ServletRequest req, String xml)
  {
    SanwafConfig cfg = this.config;
    Item item = cachedParseItem(instanceItemCache, xml,
        x -> ItemFactory.parseItem(new Xml(x), logger));
    Shield sh = (shieldName != null) ? cfg.shieldMap.get(shieldName) : null;
    if (sh == null)
    {
      if (logger.isErrorEnabled())
      {
        logger.error("Invalid ShieldName provided to isThreat():" + shieldName);
      }
      return false;
    }
    boolean result = item.inError(req, sh, value, false, false);
    if (result && req != null && cfg.onErrorAddTrackId && req.getAttribute(ATT_TRANS_ID) == null)
    {
      req.setAttribute(ATT_TRANS_ID, UUID.randomUUID().toString());
    }
    return result;
  }

  /**
   * Test if a threat is detected in a value using a given shield
   *
   * <pre>
   * Threats detected are derived from the provided shield's configuration
   * The shields stringPatterns will be executed against the value
   * No error attributes are set.
   * </pre>
   *
   * @param value
   *          the string you want to scan for threats
   * @param shieldName
   *          the shields name that you want to execute the stringPatterns from
   * @param req
   *          ServletRequest to add the error attributes
   * @return boolean true/false if a threat was detected
   */
  public boolean checkValueForShieldThreats(String value, String shieldName, ServletRequest req)
  {
    return checkValueForShieldThreats(value, shieldName, req, false);
  }

  /**
   * Test if a threat is detected in a value using a given shield
   *
   * <pre>
   * Threats detected are derived from the provided shield's configuration
   * The shields stringPatterns will be executed against the value
   * No error attributes are set.
   * </pre>
   *
   * @param value
   *          the string you want to scan for threats
   * @param shieldName
   *          the shields name that you want to execute the stringPatterns from
   * @param req
   *          ServletRequest to add the error attributes
   * @param log
   * 		  boolean value to tell sanwaf to log errors. you can get errors by calling getAllErrors(request) as errors are stored in the request attributes.
   * @return boolean true/false if a threat was detected
   */
  public boolean checkValueForShieldThreats(String value, String shieldName, ServletRequest req, boolean log)
  {
    SanwafConfig cfg = this.config;
    Shield[] shields = cfg.shields;
    for (Shield sh : shields)
    {
      if ((shieldName == null || shieldName.equals(sh.name)) && sh.threat(req, value, log))
      {
        return true;
      }
    }
    return false;
  }

  /**
   * Retrieve an allow-listed parameter/header/cookie
   *
   * <pre>{@code
   *  The header/cookie/parameter value will be returned IFF the its
   *  name is set in any Shield Metadata block
   *    <metadata>
   *      <secured>
   *        <headers></headers>
   *        <cookies></cookies>
   *        <parameters></parameters>
   *      </secured>
   *    </metadata>
   * }</pre>
   *
   * @param name
   *          the name of the header/cookie/parameter you want to retrieve
   * @param type
   *          Sanwaf.AllowListType enumeration (HEADER, COOKIE, PARAMETER)
   * @param req
   *          HttpServletRequest Object to pull the header/cookie/parameter value from
   * @return String the value of the requested header/cookie/parameter requested
   *         or null.
   */
  public String getAllowListedValue(String name, AllowListType type, HttpServletRequest req)
  {
    SanwafConfig cfg = this.config;
    Shield[] shields = cfg.shields;
    for (Shield sh : shields)
    {
      String value = sh.getAllowListedValue(name, type, req);
      if (value != null)
      {
        return value;
      }
    }
    return null;
  }

  /**
   * Dynamically reload sanwaf
   *
   */
  public void reLoad() throws IOException
  {
    instanceItemCache.clear();
    loadProperties();
  }

  /**
   * Get the Sanwaf Tracking ID
   *
   * <pre>
   * useful for displaying to your users in case they call support. this allows
   * you to pull the exact exception from the log file
   * </pre>
   *
   * @param req
   *          HttpServletRequest the request object where
   *          Sanwaf.isThreatDetected() returned true.
   * @return String returns the Sanwaf Tracking ID
   */
  public static String getTrackingId(HttpServletRequest req)
  {
    Object o = req.getAttribute(ATT_TRANS_ID);
    if (o != null)
    {
      return String.valueOf(o);
    }
    return null;
  }

  /**
   * Get Sanwaf Errors
   *
   * <pre>
   *  Returns all threats found for a give request object in JSON format
   *  used to display errors to the user.  Note that this method only returns
   *  the first error found.
   * </pre>
   *
   * @param req
   *          HttpServletRequest the request object where
   *          Sanwaf.isThreatDetected() returned true.
   * @return String Returns all threats found in JSON format
   */
  public static String getErrors(HttpServletRequest req)
  {
    return formatAttributeList(req.getAttribute(ATT_LOG_ERROR));
  }

  /**
   * Re-scan and Get All Errors
   *
   * <pre>
   *  Clears any existing error attribute, re-runs isThreatDetected on every
   *  parameter/header/cookie, and returns all threats found in JSON format.
   * </pre>
   *
   * @param req
   *          HttpServletRequest the request object where
   *          Sanwaf.isThreatDetected() returned true.
   * @return String Returns all threats found in JSON format
   */
  public String rescanAndGetAllErrors(HttpServletRequest req)
  {
    if (req == null)
    {
      return null;
    }
    SanwafConfig cfg = this.config;
    if (cfg.onErrorAddParmErrors)
    {
      //clear out the one from the block
      req.setAttribute(ATT_LOG_ERROR, null);
    }
    //call all blocks, don't worry about the detects as they will have already been processed.
    isThreatDetected(req, null, true);
    return formatAttributeList(req.getAttribute(ATT_LOG_ERROR));
  }

  /**
   * @deprecated Renamed to {@link #rescanAndGetAllErrors(HttpServletRequest)}.
   *             This method re-scans the entire request (hidden side-effect);
   *             the new name makes that explicit.
   */
  @Deprecated
  public String getAllErrors(HttpServletRequest req)
  {
    return rescanAndGetAllErrors(req);
  }

  /**
   * Get Sanwaf Detections
   *
   * <pre>
   *  Returns all threats detected & not blocked found for a give request object in JSON format
   * </pre>
   *
   * @param req
   *          HttpServletRequest the request object where
   *          Sanwaf.isThreatDetected() returned true.
   * @return String Returns all threats found in JSON format
   */
  public static String getDetects(HttpServletRequest req)
  {
    return formatAttributeList(req.getAttribute(ATT_LOG_DETECT));
  }

  @SuppressWarnings("unchecked")
  private static String formatAttributeList(Object o)
  {
    if (o instanceof Collection)
    {
      Collection<String> list = (Collection<String>) o;
      if (list.isEmpty())
      {
        return null;
      }
      return "[" + String.join(",", list) + "]";
    }
    return null;
  }

  Shield getShield(String name)
  {
    if (name == null)
    {
      return null;
    }
    return config.shieldMap.get(name);
  }

  private static <K, V> Map<K, V> createLruCache()
  {
    return Collections.synchronizedMap(
        new LinkedHashMap<K, V>(MAX_ITEM_CACHE_SIZE, 0.75f, true)
        {
          @Override
          protected boolean removeEldestEntry(Map.Entry<K, V> eldest)
          {
            return size() > MAX_ITEM_CACHE_SIZE;
          }
        });
  }

  private static Item cachedParseItem(Map<String, Item> cache, String xml,
      Function<String, Item> parser)
  {
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

  private synchronized void loadProperties() throws IOException
  {
    long start = System.currentTimeMillis();
    Xml xml;
    try
    {
      xml = new Xml(Sanwaf.class.getResource(xmlFilename));
    }
    catch (IOException e)
    {
      throw new IOException("Sanwaf Failed to load config file " + xmlFilename + ".  \n**Server is NOT protected**\n", e);
    }

    String settingsBlock = xml.get(XML_GLOBAL_SETTINGS);
    Xml settingsBlockXml = new Xml(settingsBlock);
    boolean enabled = Boolean.parseBoolean(settingsBlockXml.get(XML_ENABLED));
    boolean verbose = Boolean.parseBoolean(settingsBlockXml.get(XML_VERBOSE));
    String securedAppVersion = settingsBlockXml.get(XML_APP_VER);
    if (logger.isInfoEnabled())
    {
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
    if (logger.isInfoEnabled())
    {
      logger.info("\tAddTrackId=" + onErrorAddTrackId + "\n\tAddErrors=" + onErrorAddParmErrors + "\n\tLogErrors=" + onErrorLogParmErrors + "\n\tLogErrorsVerbose=" + onErrorLogParmErrorsVerbose
          + "\n\tAddDetections=" + onErrorAddParmDetections + "\n\tLogDetects=" + onErrorLogParmDetections + "\n\tLogDetectsVerbose=" + onErrorLogParmDetectionsVerbose);
    }

    List<Shield> shields = new ArrayList<>();
    Map<String, Shield> shieldMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    String[] shieldXMLs = xml.getAll(XML_SHIELD);
    for (String item : shieldXMLs)
    {
      Shield sh = new Shield(this, xml, new Xml(item), logger, verbose);
      shields.add(sh);
      shieldMap.put(sh.name, sh);
    }

    this.config = new SanwafConfig(enabled, verbose, onErrorAddTrackId, onErrorAddParmErrors,
        onErrorAddParmDetections, onErrorLogParmErrors, onErrorLogParmDetections,
        onErrorLogParmErrorsVerbose, onErrorLogParmDetectionsVerbose, securedAppVersion,
        shields, shieldMap, globalErrorMessages);

    if (logger.isInfoEnabled())
    {
      logger.info("Started in: " + (System.currentTimeMillis() - start) + " ms.");
    }
  }

}

