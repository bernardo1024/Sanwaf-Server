package com.sanwaf.core;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.List;

abstract class Item
{
  static final String INVALID_SIZE = "Invalid Size";
  static final String INVALID_URI = "Invalid URI";
  com.sanwaf.log.Logger logger;
  String name;
  String display;
  Shield shield;
  int max = Integer.MAX_VALUE;
  int min = 0;
  double maxValue;
  double minValue;
  String msg = null;
  String[] uri = null;
  Modes mode = Modes.BLOCK;
  boolean required = false;
  String related;
  String relatedErrMsg;
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

    if (id.display.length() == 0)
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

  // evaluate the mode, URI & size. The method returns null if no definitive
  // results was found and caller continues validation
  ModeError isModeError(ServletRequest req, String value)
  {
    ModeError me = new ModeError(false);
    if (mode == Modes.DISABLED)
    {
      return me;
    }
    else if (!isUriValid(req))
    {
      me.error = true;
      me.isUri = true;
    }
    else if (isSizeError(value))
    {
      me.error = true;
      me.isSize = true;
    }
    else
    {
      return null;
    }
    return me;
  }

  boolean isUriValid(ServletRequest req)
  {
    if (uri == null || req == null)
    {
      return true;
    }
    String reqUri = ((HttpServletRequest) req).getRequestURI();
    for (String u : uri)
    {
      if (u.equals(reqUri))
      {
        return true;
      }
    }
    return false;
  }

  boolean isSizeError(String value)
  {
    if (!required && (value == null || value.length() == 0))
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
    if (uriString != null && uriString.length() > 0)
    {
      uri = uriString.split(Shield.SEPARATOR);
    }
  }

  boolean handleMode(boolean err, String value, ServletRequest req, Modes action, boolean log)
  {
    return handleMode(err, value, req, action, log, false);
  }

  boolean handleMode(boolean err, String value, ServletRequest req, Modes action, boolean log, boolean doAllBlocks)
  {
    if (!err || Modes.DISABLED == action)
    {
      return false;
    }
    if (Modes.BLOCK == mode)
    {
      if (logger != null && log && !doAllBlocks && (shield == null || shield.sanwaf.onErrorLogParmErrors))
      {
        logger.error(toJson(value, mode, req, true));
      }
      if ((shield == null || shield.sanwaf.onErrorAddParmErrors))
      {
        appendAttribute(Sanwaf.ATT_LOG_ERROR, toJson(value, mode, req, true), req);
      }
      return err;
    }
    else
    {
      // DO DETECTS
      if (logger != null && log && (shield == null || shield.sanwaf.onErrorLogParmDetections))
      {
        logger.warn(toJson(value, mode, req, true));
      }
      if ((shield == null || shield.sanwaf.onErrorAddParmDetections))
      {
        appendAttribute(Sanwaf.ATT_LOG_DETECT, toJson(value, mode, req, true), req);
      }
    }
    return false;
  }

  static boolean handleStrictError(String value, ServletRequest req, com.sanwaf.log.Logger logger, boolean log)
  {
    ItemStrict item = new ItemStrict(value);
    if (log)
    {
      logger.error(item.toJson(item.msg, Modes.BLOCK, null, true));
    }
    appendAttribute(Sanwaf.ATT_LOG_ERROR, item.toJson(value, Modes.BLOCK, null, true), req);
    return true;
  }

  static void appendAttribute(String att, String value, ServletRequest req)
  {
    if (req == null)
    {
      return;
    }
    String old = (String) req.getAttribute(att);
    if (old == null || old.length() < 2)
    {
      old = "";
    }
    else
    {
      if (old.contains(value))
      {
        return;
      }
      old = old.substring(1, old.length() - 1) + ",";
    }
    req.setAttribute(att, "[" + old + value + "]");
  }

  boolean returnBasedOnDoAllBlocks(boolean b, boolean doAllBlocks)
  {
    if (doAllBlocks)
    {
      return false;
    }
    return b;
  }

  // Item Relations code
  String isRelateValid(String value, ServletRequest req, Metadata meta)
  {
    if (related == null || related.length() == 0)
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
    List<Boolean> orRequired = new ArrayList<>();
    List<Boolean> andRequired = new ArrayList<>();
    setAndOrConditions(value, req, andOrBlocks, orRequired, andRequired);

    int andTrueCount = 0;
    for (boolean and : andRequired)
    {
      if (and)
      {
        andTrueCount++;
      }
    }
    boolean orFoundTrue = false;
    for (boolean or : orRequired)
    {
      if (or)
      {
        orFoundTrue = true;
        break;
      }
    }
    String err = null;
    if (andTrueCount == andRequired.size() && orFoundTrue && value.length() == 0)
    {
      // TODO: add better message
      err = " - Invalid relationship detected";
    }
    return err;
  }

  private void setAndOrConditions(String value, ServletRequest req, List<String> andOrBlocks, List<Boolean> orRequired,
      List<Boolean> andRequired)
  {
    boolean nextIsAnd = false;
    boolean skipIteration = false;
    for (int i = 0; i < andOrBlocks.size(); i++)
    {
      if (skipIteration)
      {
        skipIteration = false;
        continue;
      }
      if (isRelatedBlockMakingChildRequired(andOrBlocks.get(i), value, req))
      {
        setAndOrCondition(orRequired, andRequired, nextIsAnd, true);
      }
      else
      {
        setAndOrCondition(orRequired, andRequired, nextIsAnd, false);
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
  }

  private void setAndOrCondition(List<Boolean> orRequired, List<Boolean> andRequired, boolean nextIsAnd,
      boolean value)
  {
    if (nextIsAnd)
    {
      andRequired.add(value);
    }
    else
    {
      orRequired.add(value);
    }
  }

  private List<String> parseOrBlocksFromAndBlocks(List<String> andBlocks)
  {
    List<String> andOrBlocks = new ArrayList<>();
    List<String> blocks;
    for (int i = 0; i < andBlocks.size(); i++)
    {
      blocks = parseBlocks(andBlocks.get(i), 0, "OR", ")||(", "(", ")");
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
    String[] tagKeyValuePair = block.split(":");
    String parentValue = req.getParameter(tagKeyValuePair[0]);

    int parentLen = 0;
    if (parentValue != null)
    {
      parentLen = parentValue.length();
    }

    if (tagKeyValuePair.length > 1)
    {
      String[] ors = tagKeyValuePair[1].split("\\|\\|");
      for (String or : ors)
      {
        if (or.equals(parentValue))
        {
          return true;
        }
      }
      return false;
    }

    return parentLen > 0 && value.length() == 0;
  }

  private String isRelatedEqual(String value, ServletRequest req, Metadata meta)
  {
    String[] tagKeyValuePair = related.split(":");
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
          blocks.add(s.substring(lastPos, s.length()));
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
    return toJson(null, null, null, true);
  }

  public String toJson(String value, Modes thisMode, ServletRequest req, boolean verbose)
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
      sb.append("\"shield\":{\"name\":\"").append(shield.name).append("\"");
      sb.append(",\"mode\":\"").append(shield.mode).append("\"");
      sb.append(",\"appversion\":\"").append(Sanwaf.securedAppVersion).append("\"");
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
      sb.append(",\"action\":\"").append("").append("\"");
    }
    sb.append(",\"type\":\"").append(getType()).append("\"");

    if (value != null && value.length() > 0)
    {
      sb.append(",\"value\":\"");
      String mValue = value;
      if (maskError.length() > 0)
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
      String errMsg = getErrorMessage(req, shield);
      if (required && value != null && value.length() == 0)
      {
        errMsg += getErrorMessage(req, shield, ItemFactory.XML_REQUIRED_MSG);
      }
      if (value != null && (value.length() < min || value.length() > max))
      {
        errMsg += modifyInvalidLengthErrorMsg(getErrorMessage(req, shield, ItemFactory.XML_INVALID_LENGTH_MSG), min,
            max);
      }

      if (relatedErrMsg != null && relatedErrMsg.length() > 0)
      {
        errMsg += relatedErrMsg;
      }
      sb.append(",\"error\":\"").append(Metadata.jsonEncode(errMsg)).append("\"");
    }

    if (value != null && shield != null && verbose)
    {
      List<Point> errorPoints = new ArrayList<>();
      errorPoints.addAll(getErrorPoints(shield, value));
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
      sb.append(",\"uri\":\"").append(Metadata.jsonEncode(String.valueOf(uri))).append("\"");
      sb.append(",\"req\":\"").append(required).append("\"");
      sb.append(",\"maxvalue\":\"").append(maxValue).append("\"");
      sb.append(",\"minvalue\":\"").append(minValue).append("\"");
      sb.append(",\"maskerr\":\"").append(Metadata.jsonEncode(maskError)).append("\"");
      sb.append(",\"related\":\"").append(Metadata.jsonEncode(related)).append("\"");
      String s = getProperties();
      if (s != null && s.length() > 0)
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
    if (msg != null && msg.length() > 0)
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
      if (err == null || err.length() == 0)
      {
        err = shield.sanwaf.globalErrorMessages.get(errorMsgKey);
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
          + errorMsg.substring(i + ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length(), errorMsg.length());
    }
    i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER2);
    if (i >= 0)
    {
      errorMsg = errorMsg.substring(0, i) + max
          + errorMsg.substring(i + ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length(), errorMsg.length());
    }
    return errorMsg;
  }
}
