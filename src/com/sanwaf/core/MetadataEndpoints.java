package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class MetadataEndpoints
{
  static final String XML_ENDPOINTS = "endpoints";
  static final String XML_ENDPOINT = "endpoint";
  static final String XML_STRICT = "strict";

  com.sanwaf.log.Logger logger;
  boolean enabled = false;
  boolean caseSensitive = true;
  Map<String, Metadata> endpointParametersBlock = new HashMap<>();
  Map<String, Metadata> endpointParametersDetect = new HashMap<>();
  Shield shield;

  MetadataEndpoints(Shield shield, Xml xml, com.sanwaf.log.Logger logger, boolean isDetect)
  {
    this.shield = shield;
    this.logger = logger;
    load(shield, xml, isDetect);
  }

  void load(Shield shield, Xml xml, boolean isDetect)
  {
    String metadataBlock = xml.get(Metadata.XML_METADATA);
    Xml metadataBlockXml = new Xml(metadataBlock);
    String securedBlock = metadataBlockXml.get(Metadata.XML_SECURED);
    Xml securedBlockXml = new Xml(securedBlock);

    String enabledViewBlock = metadataBlockXml.get(Shield.XML_ENABLED);
    Xml enabledViewdBlockXml = new Xml(enabledViewBlock);
    enabled = Boolean.parseBoolean(enabledViewdBlockXml.get(XML_ENDPOINTS));

    String caseBlock = metadataBlockXml.get(Shield.XML_CASE_SENSITIVE);
    Xml caseBlockXml = new Xml(caseBlock);
    caseSensitive = Boolean.parseBoolean(caseBlockXml.get(XML_ENDPOINTS));

    String endpointsBlock = securedBlockXml.get(XML_ENDPOINTS);
    Xml endpointsXml = new Xml(endpointsBlock);

    String[] xmlEndpoints = endpointsXml.getAll(XML_ENDPOINT);
    for (String endpointString : xmlEndpoints)
    {
      Xml endpointXml = new Xml(endpointString);
      String[] uris = endpointXml.get(ItemFactory.XML_ITEM_URI).split(":::");
      String strict = endpointXml.get(XML_STRICT);
      String items = endpointXml.get(ItemFactory.XML_ITEMS);
      Metadata parametersBlock = new Metadata(shield, items, caseSensitive, true, strict, logger, false);
      Metadata parametersDetect = new Metadata(shield, items, caseSensitive, true, strict, logger, true);
      setendpointparms(shield, isDetect, false, endpointString, uris, parametersBlock);
      setendpointparms(shield, isDetect, true, endpointString, uris, parametersDetect);
    }
  }

  private void setendpointparms(Shield shield, boolean isDetect, boolean isDetectParms, String endpointString, String[] uris, Metadata parameters)
  {
    int start = endpointString.indexOf("<items>");
    int end = endpointString.indexOf("</items>");
    Xml mx = new Xml(endpointString.substring(0, start) + endpointString.substring(end + "</items>".length()));
    parameters.endpointMode = Modes.getMode(mx.get(ItemFactory.XML_ITEM_MODE), (shield != null ? shield.mode : Modes.BLOCK));

    if ((!isDetect && parameters.endpointMode == Modes.BLOCK) ||
        (isDetect && (parameters.endpointMode == Modes.DETECT || parameters.endpointMode == Modes.DETECT_ALL)))
    {
      if (isDetectParms)
      {
        setEndpointParametersForUris(endpointParametersDetect, uris, parameters);
      }
      else
      {
        setEndpointParametersForUris(endpointParametersBlock, uris, parameters);
      }
    }
  }

  private void setEndpointParametersForUris(Map<String, Metadata> endpoints, String[] uris, Metadata parameters)
  {
    for (String uri : uris)
    {
      endpoints.put(uri, parameters);
    }
  }

  static boolean isStrictError(ServletRequest req, Metadata meta)
  {
    if (meta != null && meta.endpointIsStrict)
    {
      if (!meta.endpointIsStrictAllowLess)
      {
        for (String name : meta.items.keySet())
        {
          String s = req.getParameter(name);
          if (s == null)
          {
            return true;
          }
        }
      }

      Enumeration<?> names = req.getParameterNames();
      while (names.hasMoreElements())
      {
        String k = (String) names.nextElement();
        if (meta.items.get(k) == null)
        {
          return true;
        }
      }
    }
    return false;
  }

}

