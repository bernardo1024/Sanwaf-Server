package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class MetadataEndpoints
{
  static final String XML_ENDPOINTS = "endpoints";
  static final String XML_ENDPOINT = "endpoint";
  static final String XML_STRICT = "strict";

  final com.sanwaf.log.Logger logger;
  final boolean enabled;
  final boolean caseSensitive;
  final Map<String, Metadata> endpointParametersBlock;
  final Map<String, Metadata> endpointParametersDetect;

  MetadataEndpoints(Shield shield, Xml xml, com.sanwaf.log.Logger logger, boolean isDetect)
  {
    this.logger = logger;
    Metadata.ParsedMetadataXml parsed = Metadata.parseMetadataXml(xml, XML_ENDPOINTS);
    this.enabled = parsed.enabled;
    this.caseSensitive = parsed.caseSensitive;
    Map<String, Metadata> mutableBlock = new HashMap<>();
    Map<String, Metadata> mutableDetect = new HashMap<>();
    loadEndpoints(shield, parsed, isDetect, mutableBlock, mutableDetect);
    this.endpointParametersBlock = Collections.unmodifiableMap(mutableBlock);
    this.endpointParametersDetect = Collections.unmodifiableMap(mutableDetect);
  }

  private void loadEndpoints(Shield shield, Metadata.ParsedMetadataXml parsed, boolean isDetect,
      Map<String, Metadata> endpointParametersBlock, Map<String, Metadata> endpointParametersDetect)
  {
    String[] xmlEndpoints = parsed.subBlockXml.getAll(XML_ENDPOINT);
    for (String endpointString : xmlEndpoints)
    {
      Xml endpointXml = new Xml(endpointString);
      String[] uris = endpointXml.get(ItemFactory.XML_ITEM_URI).split(":::");
      String strict = endpointXml.get(XML_STRICT);
      String items = endpointXml.get(ItemFactory.XML_ITEMS);

      int start = endpointString.indexOf("<items>");
      int end = endpointString.indexOf("</items>");
      Xml mx = new Xml(endpointString.substring(0, start) + endpointString.substring(end + "</items>".length()));
      Modes mode = Modes.getMode(mx.get(ItemFactory.XML_ITEM_MODE), (shield != null ? shield.mode : Modes.BLOCK));

      boolean needed = (!isDetect && mode == Modes.BLOCK) ||
          (isDetect && (mode == Modes.DETECT || mode == Modes.DETECT_ALL));
      if (!needed)
      {
        continue;
      }

      Metadata parametersBlock = new Metadata(shield, items, caseSensitive, true, strict, logger, false, mode);
      setEndpointParametersForUris(endpointParametersBlock, uris, parametersBlock);

      Metadata parametersDetect = new Metadata(shield, items, caseSensitive, true, strict, logger, true, mode);
      setEndpointParametersForUris(endpointParametersDetect, uris, parametersDetect);
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

