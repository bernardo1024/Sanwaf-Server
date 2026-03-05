package com.sanwaf.core;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

abstract class Item
{
  com.sanwaf.log.Logger logger;
  String name;
  String display;
  Shield shield;
  int max = Integer.MAX_VALUE;
  int min = 0;
  double maxValue;
  double minValue;
  String msg = null;
  Set<String> uriSet = null;
  Modes mode = Modes.BLOCK;
  boolean required = false;
  String related;
  RelationValidator.Block[] relatedBlocks;
  String maskError = "";

  Item()
  {
  }

  Item(ItemData id)
  {
    name = id.name;
    mode = id.mode;
    shield = id.shield;
    logger = id.logger;

    if (id.display.isEmpty())
    {
      display = name;
    }
    else
    {
      display = id.display;
    }
    max = id.max;
    min = id.min;
    msg = id.msg;
    setUri(id.uri);
    required = id.required;
    maxValue = id.maxValue;
    minValue = id.minValue;
    maskError = id.maskError;
    related = id.related;
    relatedBlocks = id.relatedBlocks;
  }

  // implemented by Types
  abstract boolean inError(ServletRequest req, Shield shield, String value, boolean doAllBlocks, boolean log);

  abstract List<Point> getErrorPoints(Shield shield, String value);

  abstract Types getType();

  boolean hasPreValidationError(ServletRequest req, String value)
  {
    return mode == Modes.DISABLED || isUriInvalid(req) || isSizeError(value);
  }

  boolean isUriInvalid(ServletRequest req)
  {
    if (uriSet == null || req == null)
    {
      return false;
    }
    String reqUri = ((HttpServletRequest) req).getRequestURI();
    return !uriSet.contains(reqUri);
  }

  boolean isSizeError(String value)
  {
    if (!required && (value == null || value.isEmpty()))
    {
      return false;
    }
    if (value == null)
    {
      return true;
    }
    return (value.length() < min || value.length() > max);
  }

  String modifyErrorMsg(ServletRequest req, String errorMsg)
  {
    return errorMsg;
  }

  static String replacePlaceholder(String errorMsg, String replacement)
  {
    int i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER1);
    if (i >= 0)
    {
      int pLen = ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length();
      return errorMsg.substring(0, i) + replacement + errorMsg.substring(i + pLen);
    }
    return errorMsg;
  }

  private void setUri(String uriString)
  {
    if (uriString != null && !uriString.isEmpty())
    {
      String[] parts = uriString.split(Shield.SEPARATOR);
      uriSet = new HashSet<>(parts.length * 2);
      Collections.addAll(uriSet, parts);
    }
  }

  void handleMode(String value, ServletRequest req, Modes action, boolean log)
  {
    handleMode(value, req, action, log, false, null, null);
  }

  void handleMode(String value, ServletRequest req, Modes action, boolean log, List<Point> errorPoints)
  {
    handleMode(value, req, action, log, false, null, errorPoints);
  }

  boolean handleMode(String value, ServletRequest req, Modes action, boolean log, boolean doAllBlocks, String relatedErrMsg)
  {
    return handleMode(value, req, action, log, doAllBlocks, relatedErrMsg, null);
  }

  boolean handleMode(String value, ServletRequest req, Modes action, boolean log, boolean doAllBlocks, String relatedErrMsg, List<Point> errorPoints)
  {
    if (Modes.DISABLED == action)
    {
      return false;
    }
    Sanwaf.SanwafConfig cfg = (shield != null) ? shield.sanwaf.config : null;
    if (Modes.BLOCK == mode)
    {
      boolean doLog = logger != null && log && !doAllBlocks && (cfg == null || cfg.onErrorLogParmErrors) && logger.isErrorEnabled();
      boolean doAttr = req != null && (cfg == null || cfg.onErrorAddParmErrors);
      if (doLog || doAttr)
      {
        String json = JsonFormatter.toJson(this, value, mode, req, true, relatedErrMsg, errorPoints);
        if (doLog)
        {
          logger.error(json);
        }
        if (doAttr)
        {
          JsonFormatter.appendAttribute(Sanwaf.ATT_LOG_ERROR, json, req);
        }
      }
      return true;
    }
    else
    {
      // DETECTS
      boolean doLog = logger != null && log && (cfg == null || cfg.onErrorLogParmDetections) && logger.isWarnEnabled();
      boolean doAttr = req != null && (cfg == null || cfg.onErrorAddParmDetections);
      if (doLog || doAttr)
      {
        String json = JsonFormatter.toJson(this, value, mode, req, true, relatedErrMsg, errorPoints);
        if (doLog)
        {
          logger.warn(json);
        }
        if (doAttr)
        {
          JsonFormatter.appendAttribute(Sanwaf.ATT_LOG_DETECT, json, req);
        }
      }
    }
    return false;
  }

  String isRelateValid(String value, ServletRequest req, Metadata meta)
  {
    return RelationValidator.validate(relatedBlocks, related, value, req, meta);
  }

  String getDefaultErrorMessage()
  {
    return "Validation Error";
  }

  String getProperties()
  {
    return null;
  }

  public String toString()
  {
    return JsonFormatter.toJson(this, null, null, null, true, null, null);
  }
}
