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

  final com.sanwaf.log.Logger logger;
  boolean enabled = false;
  boolean caseSensitive = true;
  final Map<String, Metadata> endpointParametersBlock = new HashMap<>();
  final Map<String, Metadata> endpointParametersDetect = new HashMap<>();
  final Shield shield;

  MetadataEndpoints(Shield shield, Xml xml, com.sanwaf.log.Logger logger, boolean isDetect)
  {
    this.shield = shield;
    this.logger = logger;
    load(shield, xml, isDetect);
  }

  void load(Shield shield, Xml xml, boolean isDetect)
  {
    Metadata.ParsedMetadataXml parsed = Metadata.parseMetadataXml(xml, XML_ENDPOINTS);
    enabled = parsed.enabled;
    caseSensitive = parsed.caseSensitive;

    String[] xmlEndpoints = parsed.subBlockXml.getAll(XML_ENDPOINT);
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

