package com.sanwaf.core;

import com.sanwaf.log.Logger;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

abstract class Item
{
  static final String INVALID_SIZE = "Invalid Size";
  static final String INVALID_URI = "Invalid URI";
  private static final Pattern COLON_PATTERN = Pattern.compile(":");
  private static final Pattern DOUBLE_PIPE_PATTERN = Pattern.compile("\\|\\|");
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

  static void handleStrictError(String value, ServletRequest req, Logger logger, boolean log)
  {
    ItemStrict item = new ItemStrict(value);
    if (log && logger.isErrorEnabled())
    {
      logger.error(item.toJson(item.msg, Modes.BLOCK, null, true, null));
    }
    appendAttribute(Sanwaf.ATT_LOG_ERROR, item.toJson(value, Modes.BLOCK, null, true, null), req);
  }

  @SuppressWarnings("unchecked")
  static void appendAttribute(String att, String value, ServletRequest req)
  {
    if (req == null)
    {
      return;
    }
    List<String> list = (List<String>) req.getAttribute(att);
    if (list == null)
    {
      list = new ArrayList<>();
      req.setAttribute(att, list);
    }
    if (!list.contains(value))
    {
      list.add(value);
    }
  }

  // implemented by Types
  abstract boolean inError(ServletRequest req, Shield shield, String value, boolean doAllBlocks, boolean log);

  abstract List<Point> getErrorPoints(Shield shield, String value);

  abstract Types getType();

  // evaluate the mode, URI & size. The method returns null if no definitive
  // results was found and caller continues validation
  ModeError isModeError(ServletRequest req, String value)
  {
    if (mode == Modes.DISABLED || !isUriValid(req) || isSizeError(value))
    {
      return ModeError.INSTANCE;
    }
    return null;
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
        String json = toJson(value, mode, req, true, relatedErrMsg);
        if (doLog)
        {
          logger.error(json);
        }
        if (doAttr)
        {
          appendAttribute(Sanwaf.ATT_LOG_ERROR, json, req);
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
        String json = toJson(value, mode, req, true, relatedErrMsg);
        if (doLog)
        {
          logger.warn(json);
        }
        if (doAttr)
        {
          appendAttribute(Sanwaf.ATT_LOG_DETECT, json, req);
        }
      }
    }
    return false;
  }

  // Item Relations code
  String isRelateValid(String value, ServletRequest req, Metadata meta)
  {
    if (related == null || related.isEmpty())
    {
      return null;
    }
    // check if simple equals condition
    if (related.endsWith(":="))
    {
      return isRelatedEqual(value, req, meta);
    }

    List<String> andBlocks = parseBlocks(related, 0, "AND", ")&&(", "(", ")");
    List<String> andOrBlocks = parseOrBlocksFromAndBlocks(andBlocks);
    int andTrueCount = 0;
    int andTotalCount = 0;
    boolean orFoundTrue = false;
    boolean nextIsAnd = false;
    boolean skipIteration = false;
    for (int i = 0; i < andOrBlocks.size(); i++)
    {
      if (skipIteration)
      {
        skipIteration = false;
        continue;
      }
      boolean condResult = isRelatedBlockMakingChildRequired(andOrBlocks.get(i), value, req);
      if (nextIsAnd)
      {
        andTotalCount++;
        if (condResult)
        {
          andTrueCount++;
        }
      }
      else if (condResult)
      {
        orFoundTrue = true;
      }
      nextIsAnd = false;
      if (andOrBlocks.size() > i + 1)
      {
        if (andOrBlocks.get(i + 1).equals("AND"))
        {
          nextIsAnd = true;
        }
        skipIteration = true;
      }
    }
    String err = null;
    if (andTrueCount == andTotalCount && orFoundTrue && value.isEmpty())
    {
      // TODO: add better message
      err = " - Invalid relationship detected";
    }
    return err;
  }


  private List<String> parseOrBlocksFromAndBlocks(List<String> andBlocks)
  {
    List<String> andOrBlocks = new ArrayList<>();
    List<String> blocks;
    for (String andBlock : andBlocks)
    {
      blocks = parseBlocks(andBlock, 0, "OR", ")||(", "(", ")");
      for (int j = 0; j < blocks.size(); j++)
      {
        if (blocks.get(j).equals("||"))
        {
          blocks.set(j, "OR");
        }
        else if (blocks.get(j).endsWith(")||"))
        {
          String block = blocks.get(j);
          blocks.set(j, block.substring(1, block.length() - 3));
          blocks.add(j + 1, "OR");
        }
      }
      andOrBlocks.addAll(blocks);
    }
    return andOrBlocks;
  }

  private boolean isRelatedBlockMakingChildRequired(String block, String value, ServletRequest req)
  {
    String[] tagKeyValuePair = COLON_PATTERN.split(block);
    String parentValue = req.getParameter(tagKeyValuePair[0]);

    int parentLen = 0;
    if (parentValue != null)
    {
      parentLen = parentValue.length();
    }

    if (tagKeyValuePair.length > 1)
    {
      String[] ors = DOUBLE_PIPE_PATTERN.split(tagKeyValuePair[1]);
      for (String or : ors)
      {
        if (or.equals(parentValue))
        {
          return true;
        }
      }
      return false;
    }

    return parentLen > 0 && value.isEmpty();
  }

  private String isRelatedEqual(String value, ServletRequest req, Metadata meta)
  {
    String[] tagKeyValuePair = COLON_PATTERN.split(related);
    String parentValue = req.getParameter(tagKeyValuePair[0]);
    if (value.equals(parentValue))
    {
      return null;
    }
    Item parentItem = meta.items.get(tagKeyValuePair[0]);
    return parentItem == null ? null : " - does not match \"" + parentItem.display + "\"";
  }

  private List<String> parseBlocks(String s, int start, String andOr, String match, String reverseMatch,
      String forwardMatch)
  {
    List<String> blocks = new ArrayList<>();
    int lastPos = start;
    while (true)
    {
      int pos = s.indexOf(match, lastPos);
      if (pos > 0)
      {
        start = s.lastIndexOf(reverseMatch, pos);
        if (start != lastPos)
        {
          blocks.add(s.substring(lastPos, start));
        }
        blocks.add(s.substring(start + reverseMatch.length(), pos));
        blocks.add(andOr);
        int end = s.indexOf(forwardMatch, pos + match.length());
        blocks.add(s.substring(pos + match.length(), end));
        lastPos = end + forwardMatch.length();
      }
      else
      {
        if (lastPos + 1 < s.length())
        {
          blocks.add(s.substring(lastPos));
        }
        break;
      }
    }
    return blocks;
  }

  //log code
  String getProperties()
  {
    return null;
  }

  public String toString()
  {
    return toJson(null, null, null, true, null);
  }

  public String toJson(String value, Modes thisMode, ServletRequest req, boolean verbose, String relatedErrMsg)
  {
    StringBuilder sb = new StringBuilder();
    sb.append("{");

    if (req != null)
    {
      HttpServletRequest hreq = (HttpServletRequest) req;
      sb.append("\"transid\":\"").append(hreq.getAttribute(Metadata.jsonEncode(Sanwaf.ATT_TRANS_ID))).append("\"");
      sb.append(",\"ip\":\"").append(hreq.getRemoteAddr()).append("\"");
      sb.append(",\"referer\":\"").append(Metadata.jsonEncode(hreq.getHeader("referer"))).append("\",");
    }

    if (shield != null && verbose)
    {
      Sanwaf.SanwafConfig c = shield.sanwaf.config;
      sb.append("\"shield\":{\"name\":\"").append(shield.name).append("\"");
      sb.append(",\"mode\":\"").append(shield.mode).append("\"");
      sb.append(",\"appversion\":\"").append(c != null ? c.securedAppVersion : "").append("\"");
      sb.append("},");
    }

    sb.append("\"item\":{\"name\":\"").append(Metadata.jsonEncode(name)).append("\"");
    sb.append(",\"display\":\"").append(Metadata.jsonEncode(display)).append("\"");
    sb.append(",\"mode\":\"").append(mode).append("\"");
    if (thisMode != null)
    {
      sb.append(",\"action\":\"").append(thisMode).append("\"");
    }
    else
    {
      sb.append(",\"action\":\"").append("\"");
    }
    sb.append(",\"type\":\"").append(getType()).append("\"");

    if (value != null && !value.isEmpty())
    {
      sb.append(",\"value\":\"");
      String mValue = value;
      if (!maskError.isEmpty())
      {
        mValue = maskError;
      }
      sb.append(Metadata.jsonEncode(mValue.length() < 100 ? mValue : (mValue.substring(0, 100) + "..."))).append("\"");
    }
    else
    {
      sb.append(",\"value\":\"").append(value).append("\"");
    }

    if (shield != null)
    {
      StringBuilder errMsg = new StringBuilder();
      errMsg.append(getErrorMessage(req, shield));
      if (required && value != null && value.isEmpty())
      {
        errMsg.append(getErrorMessage(req, shield, ItemFactory.XML_REQUIRED_MSG));
      }
      if (value != null && (value.length() < min || value.length() > max))
      {
        errMsg.append(modifyInvalidLengthErrorMsg(getErrorMessage(req, shield, ItemFactory.XML_INVALID_LENGTH_MSG), min, max));
      }

      if (relatedErrMsg != null && !relatedErrMsg.isEmpty())
      {
        errMsg.append(relatedErrMsg);
      }
      sb.append(",\"error\":\"").append(Metadata.jsonEncode(errMsg.toString())).append("\"");
    }

    if (value != null && shield != null && verbose)
    {
      List<Point> errorPoints = new ArrayList<>(getErrorPoints(shield, value));
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

    if (shield != null && verbose)
    {
      sb.append(",\"properties\": {");
      sb.append("\"maxlength\":\"").append(max).append("\"");
      sb.append(",\"minlength\":\"").append(min).append("\"");
      sb.append(",\"msg\":\"").append(Metadata.jsonEncode(msg)).append("\"");
      sb.append(",\"uri\":\"").append(Metadata.jsonEncode(String.valueOf(uriSet))).append("\"");
      sb.append(",\"req\":\"").append(required).append("\"");
      sb.append(",\"maxvalue\":\"").append(maxValue).append("\"");
      sb.append(",\"minvalue\":\"").append(minValue).append("\"");
      sb.append(",\"maskerr\":\"").append(Metadata.jsonEncode(maskError)).append("\"");
      sb.append(",\"related\":\"").append(Metadata.jsonEncode(related)).append("\"");
      String s = getProperties();
      if (s != null && !s.isEmpty())
      {
        sb.append(",").append(s);
      }
      sb.append("}}");
    }
    sb.append("}");
    return sb.toString();
  }

  String getErrorMessage(final ServletRequest req, final Shield shield)
  {
    return getErrorMessage(req, shield, null);
  }

  String getErrorMessage(final ServletRequest req, final Shield shield, String errorMsgKey)
  {
    String err = null;
    if (msg != null && !msg.isEmpty())
    {
      err = msg;
    }
    if (err == null)
    {

      // NEED TO check the rule error msg first, then, shield, then global

      if (errorMsgKey == null)
      {
        errorMsgKey = getType().toString();
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
    return modifyErrorMsg(req, err);
  }

  String modifyInvalidLengthErrorMsg(String errorMsg, int min, int max)
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
