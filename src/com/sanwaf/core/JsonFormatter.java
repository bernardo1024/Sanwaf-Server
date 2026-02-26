package com.sanwaf.core;

import com.sanwaf.log.Logger;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class JsonFormatter
{
  private JsonFormatter()
  {
  }

  static void handleStrictError(String value, ServletRequest req, Logger logger, boolean log)
  {
    String json = formatStrictErrorJson(value);
    if (log && logger.isErrorEnabled())
    {
      logger.error(json);
    }
    appendAttribute(Sanwaf.ATT_LOG_ERROR, json, req);
  }

  static String formatStrictErrorJson(String value)
  {
    StringBuilder sb = new StringBuilder(256);
    sb.append("{\"item\":{\"name\":\"\"");
    sb.append(",\"display\":\"\"");
    sb.append(",\"mode\":\"BLOCK\"");
    sb.append(",\"action\":\"BLOCK\"");
    sb.append(",\"type\":\"STRICT\"");
    if (value != null && !value.isEmpty())
    {
      sb.append(",\"value\":\"").append(Metadata.jsonEncode(value.length() < 100 ? value : (value.substring(0, 100) + "..."))).append("\"");
    }
    else
    {
      sb.append(",\"value\":\"").append(value).append("\"");
    }
    sb.append("}}");
    return sb.toString();
  }

  @SuppressWarnings("unchecked")
  static void appendAttribute(String att, String value, ServletRequest req)
  {
    if (req == null)
    {
      return;
    }
    Set<String> set = (Set<String>) req.getAttribute(att);
    if (set == null)
    {
      set = new LinkedHashSet<>();
      req.setAttribute(att, set);
    }
    set.add(value);
  }

  static String toJson(Item item, String value, Modes thisMode, ServletRequest req, boolean verbose, String relatedErrMsg)
  {
    StringBuilder sb = new StringBuilder(512);
    sb.append("{");

    if (req != null)
    {
      HttpServletRequest hreq = (HttpServletRequest) req;
      sb.append("\"transid\":\"").append(hreq.getAttribute(Metadata.jsonEncode(Sanwaf.ATT_TRANS_ID))).append("\"");
      sb.append(",\"ip\":\"").append(hreq.getRemoteAddr()).append("\"");
      sb.append(",\"referer\":\"").append(Metadata.jsonEncode(hreq.getHeader("referer"))).append("\",");
    }

    if (item.shield != null && verbose)
    {
      Sanwaf.SanwafConfig c = item.shield.sanwaf.config;
      sb.append("\"shield\":{\"name\":\"").append(item.shield.name).append("\"");
      sb.append(",\"mode\":\"").append(item.shield.mode).append("\"");
      sb.append(",\"appversion\":\"").append(c != null ? c.securedAppVersion : "").append("\"");
      sb.append("},");
    }

    sb.append("\"item\":{\"name\":\"").append(Metadata.jsonEncode(item.name)).append("\"");
    sb.append(",\"display\":\"").append(Metadata.jsonEncode(item.display)).append("\"");
    sb.append(",\"mode\":\"").append(item.mode).append("\"");
    if (thisMode != null)
    {
      sb.append(",\"action\":\"").append(thisMode).append("\"");
    }
    else
    {
      sb.append(",\"action\":\"").append("\"");
    }
    sb.append(",\"type\":\"").append(item.getType()).append("\"");

    if (value != null && !value.isEmpty())
    {
      sb.append(",\"value\":\"");
      String mValue = value;
      if (!item.maskError.isEmpty())
      {
        mValue = item.maskError;
      }
      sb.append(Metadata.jsonEncode(mValue.length() < 100 ? mValue : (mValue.substring(0, 100) + "..."))).append("\"");
    }
    else
    {
      sb.append(",\"value\":\"").append(value).append("\"");
    }

    if (item.shield != null)
    {
      StringBuilder errMsg = new StringBuilder();
      errMsg.append(getErrorMessage(item, req, item.shield));
      if (item.required && value != null && value.isEmpty())
      {
        errMsg.append(getErrorMessage(item, req, item.shield, ItemFactory.XML_REQUIRED_MSG));
      }
      if (value != null && (value.length() < item.min || value.length() > item.max))
      {
        errMsg.append(modifyInvalidLengthErrorMsg(getErrorMessage(item, req, item.shield, ItemFactory.XML_INVALID_LENGTH_MSG), item.min, item.max));
      }

      if (relatedErrMsg != null && !relatedErrMsg.isEmpty())
      {
        errMsg.append(relatedErrMsg);
      }
      sb.append(",\"error\":\"").append(Metadata.jsonEncode(errMsg.toString())).append("\"");
    }

    if (value != null && item.shield != null && verbose)
    {
      List<Point> errorPoints = item.getErrorPoints(item.shield, value);
      sb.append(",\"samplePoints\":[");
      boolean doneFirst = false;
      for (Point p : errorPoints)
      {
        if (doneFirst)
        {
          sb.append(",");
        }
        else
        {
          doneFirst = true;
        }
        sb.append("{\"start\":\"").append(p.start).append("\"");
        sb.append(",\"end\":\"").append(p.end).append("\"}");
      }
      sb.append("]");
    }

    if (item.shield != null && verbose)
    {
      sb.append(",\"properties\": {");
      sb.append("\"maxlength\":\"").append(item.max).append("\"");
      sb.append(",\"minlength\":\"").append(item.min).append("\"");
      sb.append(",\"msg\":\"").append(Metadata.jsonEncode(item.msg)).append("\"");
      sb.append(",\"uri\":\"").append(Metadata.jsonEncode(String.valueOf(item.uriSet))).append("\"");
      sb.append(",\"req\":\"").append(item.required).append("\"");
      sb.append(",\"maxvalue\":\"").append(item.maxValue).append("\"");
      sb.append(",\"minvalue\":\"").append(item.minValue).append("\"");
      sb.append(",\"maskerr\":\"").append(Metadata.jsonEncode(item.maskError)).append("\"");
      sb.append(",\"related\":\"").append(Metadata.jsonEncode(item.related)).append("\"");
      String s = item.getProperties();
      if (s != null && !s.isEmpty())
      {
        sb.append(",").append(s);
      }
      sb.append("}}");
    }
    sb.append("}");
    return sb.toString();
  }

  static String getErrorMessage(Item item, ServletRequest req, Shield shield)
  {
    return getErrorMessage(item, req, shield, null);
  }

  static String getErrorMessage(Item item, ServletRequest req, Shield shield, String errorMsgKey)
  {
    String err = null;
    if (item.msg != null && !item.msg.isEmpty())
    {
      err = item.msg;
    }
    if (err == null)
    {
      if (errorMsgKey == null)
      {
        errorMsgKey = item.getType().toString();
      }
      err = shield.errorMessages.get(errorMsgKey);
      if (err == null || err.isEmpty())
      {
        Sanwaf.SanwafConfig c = shield.sanwaf.config;
        if (c != null)
        {
          err = c.globalErrorMessages.get(errorMsgKey);
        }
      }
    }
    if (err == null || err.isEmpty())
    {
      err = item.getDefaultErrorMessage();
    }
    return item.modifyErrorMsg(req, err);
  }

  static String modifyInvalidLengthErrorMsg(String errorMsg, int min, int max)
  {
    int i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER1);
    if (i >= 0)
    {
      errorMsg = errorMsg.substring(0, i) + min
          + errorMsg.substring(i + ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length());
    }
    i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER2);
    if (i >= 0)
    {
      errorMsg = errorMsg.substring(0, i) + max
          + errorMsg.substring(i + ItemFactory.XML_ERROR_MSG_PLACEHOLDER2.length());
    }
    return errorMsg;
  }
}
