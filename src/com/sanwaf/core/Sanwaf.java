package com.sanwaf.core;

import com.sanwaf.log.Logger;
import com.sanwaf.log.SimpleLogger;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class Sanwaf
{
  static final String DEFAULT_LOGGER_DETECTED_MSG = "NOTE: Sanwaf is using the Default \"SimpleLogger\" logger."
      + " To correct this, implement the com.sanwaf.log.Logger Interface and provide your logger in the Sanwaf constructor.";
  static final String STANDALONE_XML_FILENAME = "sanwaf.xml";
  static final String ATT_LOG_ERROR = "~sanwaf-errors";
  static final String ATT_LOG_DETECT = "~sanwaf-detects";
  static final String ATT_TRANS_ID = "~sanwaf-id";

  private String xmlFilename = null;
  final Logger logger;

  boolean enabled = false;
  boolean verbose = false;
  boolean onErrorAddTrackId = true;
  boolean onErrorAddParmErrors = true;
  boolean onErrorAddParmDetections = true;
  boolean onErrorLogParmErrors = true;
  boolean onErrorLogParmDetections = true;
  boolean onErrorLogParmErrorsVerbose = true;
  boolean onErrorLogParmDetectionsVerbose = true;

  static String securedAppVersion = "unknown";
  final List<Shield> shields = new ArrayList<>();
  final Map<String, Shield> shieldMap = new HashMap<>();
  final Map<String, String> globalErrorMessages = new HashMap<>();

  public enum AllowListType
  {
    HEADER, COOKIE, PARAMETER
  }

  /**
   * Default Sanwaf constructor.
   *
   * <pre>
   * Creates a in instance of Sanwaf initializing it with:
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
    return isThreatDetected(req, false);
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
   * 		  flag to control if sawaf will log errors detected. you can use the getAllErrors method to pull errors from the request object
   * @return boolean true/false if a threat was detected
   */
  public boolean isThreatDetected(ServletRequest req, List<String> shieldList, boolean doAllBlocks, boolean log)
  {
    boolean threat = false;
    if (req != null && onErrorAddTrackId)
    {
      req.setAttribute(ATT_TRANS_ID, UUID.randomUUID());
    }

    if (!enabled || !(req instanceof HttpServletRequest))
    {
      return false;
    }
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
   * configure sanwaf with xml inline for validations
   * </pre>
   *
   * @param value
   *          the shields name that you want to execute the stringPatterns from
   * @param sXml
   *          item xml to be used to validate with
   * @return boolean true/false if a threat was detected
   */
  public static boolean isThreat(String value, String sXml)
  {
    Item item = ItemFactory.parseItem(null, new Xml(sXml), false, null);
    return item.inError(null, null, value, false, false);
  }

  /**
   * Test if a threat is detected in a value using a given shield
   *
   * <pre>
   * Threats detected are derived from the provided shield's configuration
   * The shields stringPatterns will be executed against the value
   * Error attributes will be set if specified
   * If an error is detected, attributes will be added to request for processing latter.  
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
    if (req != null && onErrorAddTrackId)
    {
      req.setAttribute(ATT_TRANS_ID, UUID.randomUUID());
    }
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
   * If an error is detected, attributes will be added to request for processing latter.  
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
    if (req != null && onErrorAddTrackId)
    {
      req.setAttribute(ATT_TRANS_ID, UUID.randomUUID());
    }
    Item item = ItemFactory.parseItem(null, new Xml(xml), logger);
    Shield sh = getShield(shieldName);
    if (sh == null)
    {
      logger.error("Invalid ShieldName provided to isThreat():" + shieldName);
      return false;
    }
    return item.inError(req, sh, value, false, false);
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
    for (Shield sh : shields)
    {
      if ((shieldName == null || shieldName.contains(sh.name)) && sh.threat(req, null, "", value, false, log))
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
    Object o = req.getAttribute(ATT_LOG_ERROR);
    if (o != null)
    {
      return String.valueOf(o);
    }
    return null;
  }

  /**
   * Get All Sanwaf Errors
   *
   * <pre>
   *  Returns all threats found for a give request object in JSON format
   *  used to display errors to the user.
   *  This method returns all errors detected.
   * </pre>
   *
   * @param req
   *          HttpServletRequest the request object where
   *          Sanwaf.isThreatDetected() returned true.
   * @return String Returns all threats found in JSON format
   */
  public String getAllErrors(HttpServletRequest req)
  {
    if (req == null)
    {
      return null;
    }
    if (onErrorAddParmErrors)
    {
      //clear out the one from the block
      req.setAttribute(ATT_LOG_ERROR, "");
    }
    //call all blocks, dont worry about the detects as they will have already been processed.
    isThreatDetected(req, null, true);
    Object o = req.getAttribute(ATT_LOG_ERROR);
    if (o != null)
    {
      return String.valueOf(o);
    }
    return null;
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
    Object o = req.getAttribute(ATT_LOG_DETECT);
    if (o != null)
    {
      return String.valueOf(o);
    }
    return null;
  }

  Shield getShield(String name)
  {
    if (name == null)
    {
      return null;
    }
    return shieldMap.get(name.toLowerCase());
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
    enabled = Boolean.parseBoolean(settingsBlockXml.get(XML_ENABLED));
    verbose = Boolean.parseBoolean(settingsBlockXml.get(XML_VERBOSE));
    securedAppVersion = settingsBlockXml.get(XML_APP_VER);
    logger.info("Starting Sanwaf:");
    logger.info("\n\tenabled=" + enabled + "\n\t" + XML_VERBOSE + "=" + verbose + "\n\t" + XML_APP_VER + "=" + securedAppVersion);

    String errorBlock = xml.get(XML_ERR_HANDLING);
    Xml errorBlockXml = new Xml(errorBlock);
    onErrorAddTrackId = Boolean.parseBoolean(errorBlockXml.get(XML_ERR_SET_ATT_TRACK_ID));
    onErrorAddParmErrors = Boolean.parseBoolean(errorBlockXml.get(XML_SET_ATT_PARM_ERR));
    onErrorAddParmDetections = Boolean.parseBoolean(errorBlockXml.get(XML_SET_ATT_PARM_DETECT));
    onErrorLogParmErrors = Boolean.parseBoolean(errorBlockXml.get(XML_LOG_PARM_ERR));
    onErrorLogParmDetections = Boolean.parseBoolean(errorBlockXml.get(XML_LOG_PARM_DETECT));
    onErrorLogParmErrorsVerbose = Boolean.parseBoolean(errorBlockXml.get(XML_LOG_PARM_ERR_VERB));
    onErrorLogParmDetectionsVerbose = Boolean.parseBoolean(errorBlockXml.get(XML_LOG_PARM_DETECT_VERB));

    ItemFactory.setErrorMessages(globalErrorMessages, xml);
    logger.info("\tAddTrackId=" + onErrorAddTrackId + "\n\tAddErrors=" + onErrorAddParmErrors + "\n\tLogErrors=" + onErrorLogParmErrors + "\n\tLogErrorsVerbose=" + onErrorLogParmErrorsVerbose
        + "\n\tAddDetections=" + onErrorAddParmDetections + "\n\tLogDetects=" + onErrorLogParmDetections + "\n\tLogDetectsVerbose=" + onErrorLogParmDetectionsVerbose);

    String[] xmls = xml.getAll(XML_SHIELD);
    for (String item : xmls)
    {
      Shield sh = new Shield(this, xml, new Xml(item), logger);
      shields.add(sh);
      shieldMap.put(sh.name.toLowerCase(), sh);
    }
    logger.info("Started in: " + (System.currentTimeMillis() - start) + " ms.");
  }

}

