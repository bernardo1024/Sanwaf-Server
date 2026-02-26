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
  String maskError = "";

  Item()
  {
  }

  Item(ItemData id)
  {
    name = id.name;
    mode = id.mode;
    shield = id.shield;
    if (shield != null)
    {
      logger = id.shield.logger;
    }

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
  }

  // implemented by Types
  abstract boolean inError(ServletRequest req, Shield shield, String value, boolean doAllBlocks, boolean log);

  abstract List<Point> getErrorPoints(Shield shield, String value);

  abstract Types getType();

  boolean shouldSkipValidation(ServletRequest req, String value)
  {
    return mode == Modes.DISABLED || !isUriValid(req) || isSizeError(value);
  }

  boolean isUriValid(ServletRequest req)
  {
    if (uriSet == null || req == null)
    {
      return true;
    }
    String reqUri = ((HttpServletRequest) req).getRequestURI();
    return uriSet.contains(reqUri);
  }

  boolean isSizeError(String value)
  {
    if (!required && (value == null || value.isEmpty()))
    {
      return false;
    }
    return (value.length() < min || value.length() > max);
  }

  String modifyErrorMsg(ServletRequest req, String errorMsg)
  {
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

  boolean handleMode(boolean err, String value, ServletRequest req, Modes action, boolean log, String relatedErrMsg)
  {
    return handleMode(err, value, req, action, log, false, relatedErrMsg);
  }

  boolean handleMode(boolean err, String value, ServletRequest req, Modes action, boolean log, boolean doAllBlocks, String relatedErrMsg)
  {
    if (!err || Modes.DISABLED == action)
    {
      return false;
    }
    Sanwaf.SanwafConfig cfg = (shield != null) ? shield.sanwaf.config : null;
    if (Modes.BLOCK == mode)
    {
      boolean doLog = logger != null && log && !doAllBlocks && (cfg == null || cfg.onErrorLogParmErrors) && logger.isErrorEnabled();
      boolean doAttr = (cfg == null || cfg.onErrorAddParmErrors);
      if (doLog || doAttr)
      {
        String json = JsonFormatter.toJson(this, value, mode, req, true, relatedErrMsg);
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
      // DO DETECTS
      boolean doLog = logger != null && log && (cfg == null || cfg.onErrorLogParmDetections) && logger.isWarnEnabled();
      boolean doAttr = (cfg == null || cfg.onErrorAddParmDetections);
      if (doLog || doAttr)
      {
        String json = JsonFormatter.toJson(this, value, mode, req, true, relatedErrMsg);
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
    return RelationValidator.validate(related, value, req, meta);
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
    return JsonFormatter.toJson(this, null, null, null, true, null);
  }
}
