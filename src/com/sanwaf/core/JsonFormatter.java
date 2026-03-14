package com.sanwaf.core;

import com.sanwaf.log.Logger;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Utility class that builds JSON-formatted error and log messages for
 * Sanwaf validation results.
 *
 * <p>All methods are static. The class also provides low-level JSON string
 * encoding that escapes special characters, control codes, and Unicode line
 * separators.
 */
final class JsonFormatter {
  /**
   * Pre-computed {@code \\u00xx} escape sequences for ASCII control characters
   * (code points 0x00 through 0x1F).
   */
  private static final String[] CTRL_UNICODE_ESCAPES = new String[0x20];

  static {
    char[] hex = "0123456789abcdef".toCharArray();
    for (int i = 0; i < 0x20; i++) {
      CTRL_UNICODE_ESCAPES[i] = "\\u00" + hex[i >> 4] + hex[i & 0xF];
    }
  }

  /** Prevents instantiation. */
  private JsonFormatter() {
  }

  /**
   * Formats and records a strict-mode validation error.
   *
   * <p>The error is formatted as JSON and optionally logged. It is also
   * appended to the request attribute identified by
   * {@link Sanwaf#ATT_LOG_ERROR}.
   *
   * @param value  the offending parameter value
   * @param req    the current servlet request
   * @param logger the logger instance for error output
   * @param log    {@code true} to write to the logger in addition to the
   *               request attribute
   */
  static void handleStrictError(String value, ServletRequest req, Logger logger, boolean log) {
    String json = formatStrictErrorJson(value);
    if (log && logger.isErrorEnabled()) {
      logger.error(json);
    }
    appendAttribute(Sanwaf.ATT_LOG_ERROR, json, req);
  }

  /**
   * Builds a JSON string representing a strict-mode validation error.
   *
   * @param value the offending parameter value (truncated to 100 chars in output)
   * @return the JSON error string
   */
  static String formatStrictErrorJson(String value) {
    StringBuilder sb = new StringBuilder(256);
    sb.append("{\"item\":{\"name\":\"\"");
    sb.append(",\"display\":\"\"");
    sb.append(",\"mode\":\"BLOCK\"");
    sb.append(",\"action\":\"BLOCK\"");
    sb.append(",\"type\":\"STRICT\"");
    if (value != null && !value.isEmpty()) {
      sb.append(",\"value\":\"");
      if (value.length() < 100) {
        sb.append(jsonEncode(value));
      } else {
        sb.append(jsonEncodeTruncated(value)).append("...");
      }
      sb.append("\"");
    } else {
      sb.append(",\"value\":\"\"");
    }
    sb.append("}}");
    return sb.toString();
  }

  /**
   * Appends a value to a {@link Set} stored as a request attribute.
   *
   * <p>If the attribute does not yet exist, a new {@link LinkedHashSet} is
   * created and set on the request.
   *
   * @param att   the attribute name
   * @param value the value to add to the set
   * @param req   the servlet request; if {@code null} the call is a no-op
   */
  static void appendAttribute(String att, String value, ServletRequest req) {
    if (req == null) {
      return;
    }
    Object o = req.getAttribute(att);
    Set<String> set = null;
    if (o instanceof Set) {
      @SuppressWarnings("unchecked")
      Set<String> tmp = (Set<String>) o;
      set = tmp;
    }
    if (set == null) {
      set = new LinkedHashSet<>();
      req.setAttribute(att, set);
    }
    set.add(value);
  }

  /**
   * Serialises a full validation-error report for an {@link Item} as JSON.
   *
   * <p>When {@code verbose} is {@code true} the output includes shield
   * metadata, sample error points, and detailed item properties.
   *
   * @param item          the item that failed validation
   * @param value         the offending parameter value
   * @param thisMode      the effective mode for this failure (may differ from
   *                      the item's configured mode)
   * @param req           the current servlet request; used for transaction ID,
   *                      IP, and referer
   * @param verbose       {@code true} to include shield info and item properties
   * @param relatedErrMsg additional error text from related-field validation;
   *                      may be {@code null}
   * @param errorPoints   pre-computed error points, or {@code null} to compute
   *                      them on the fly
   * @return the JSON error string
   */
  static String toJson(Item item, String value, Modes thisMode, ServletRequest req, boolean verbose, String relatedErrMsg, List<Point> errorPoints) {
    StringBuilder sb = new StringBuilder(512);
    sb.append("{");

    if (req != null) {
      HttpServletRequest httpReq = (HttpServletRequest) req;
      Object transId = httpReq.getAttribute(Sanwaf.ATT_TRANS_ID);
      if (transId == null) {
        transId = UUID.randomUUID().toString();
        httpReq.setAttribute(Sanwaf.ATT_TRANS_ID, transId);
      }
      //noinspection SpellCheckingInspection
      sb.append("\"transid\":\"").append(transId).append("\"");
      sb.append(",\"ip\":\"").append(httpReq.getRemoteAddr()).append("\"");
      sb.append(",\"referer\":\"").append(jsonEncode(httpReq.getHeader("referer"))).append("\",");
    }

    if (item.shield != null && verbose) {
      Sanwaf.SanwafConfig c = item.shield.sanwaf.config;
      sb.append("\"shield\":{\"name\":\"").append(item.shield.name).append("\"");
      sb.append(",\"mode\":\"").append(item.shield.mode).append("\"");
      //noinspection SpellCheckingInspection
      sb.append(",\"appversion\":\"").append(c != null ? c.securedAppVersion : "").append("\"");
      sb.append("},");
    }

    sb.append("\"item\":{\"name\":\"").append(jsonEncode(item.name)).append("\"");
    sb.append(",\"display\":\"").append(jsonEncode(item.display)).append("\"");
    sb.append(",\"mode\":\"").append(item.mode).append("\"");
    if (thisMode != null) {
      sb.append(",\"action\":\"").append(thisMode).append("\"");
    } else {
      sb.append(",\"action\":\"").append("\"");
    }
    sb.append(",\"type\":\"").append(item.getType()).append("\"");

    if (value != null && !value.isEmpty()) {
      sb.append(",\"value\":\"");
      String mValue = value;
      if (!item.maskError.isEmpty()) {
        mValue = item.maskError;
      }
      if (mValue.length() < 100) {
        sb.append(jsonEncode(mValue));
      } else {
        sb.append(jsonEncodeTruncated(mValue)).append("...");
      }
      sb.append("\"");
    } else {
      sb.append(",\"value\":\"\"");
    }

    if (item.shield != null) {
      String baseErr = getErrorMessage(item, req, item.shield);
      boolean needsRequired = item.required && value != null && value.isEmpty();
      boolean needsLength = value != null && (value.length() < item.min || value.length() > item.max);
      boolean needsRelated = relatedErrMsg != null && !relatedErrMsg.isEmpty();
      String errMsg;
      if (!needsRequired && !needsLength && !needsRelated) {
        errMsg = baseErr;
      } else {
        StringBuilder errSb = new StringBuilder(baseErr);
        if (needsRequired) {
          errSb.append(getErrorMessage(item, req, item.shield, ItemFactory.XML_REQUIRED_MSG));
        }
        if (needsLength) {
          errSb.append(modifyInvalidLengthErrorMsg(getErrorMessage(item, req, item.shield, ItemFactory.XML_INVALID_LENGTH_MSG), item.min, item.max));
        }
        if (needsRelated) {
          errSb.append(relatedErrMsg);
        }
        errMsg = errSb.toString();
      }
      sb.append(",\"error\":\"").append(jsonEncode(errMsg)).append("\"");
    }

    if (value != null && item.shield != null && verbose) {
      List<Point> points;
      if (errorPoints != null && item.maskError.isEmpty()) {
        points = errorPoints;
      } else {
        points = item.getErrorPoints(item.shield, value);
      }
      sb.append(",\"samplePoints\":[");
      boolean doneFirst = false;
      for (Point p : points) {
        if (doneFirst) {
          sb.append(",");
        } else {
          doneFirst = true;
        }
        sb.append("{\"start\":\"").append(p.start).append("\"");
        sb.append(",\"end\":\"").append(p.end).append("\"}");
      }
      sb.append("]");
    }

    if (item.shield != null && verbose) {
      sb.append(",\"properties\": {");
      sb.append("\"maxlength\":\"").append(item.max).append("\"");
      sb.append(",\"minlength\":\"").append(item.min).append("\"");
      sb.append(",\"msg\":\"").append(jsonEncode(item.msg)).append("\"");
      sb.append(",\"uri\":\"");
      if (item.uriSet != null) {
        boolean first = true;
        for (String u : item.uriSet) {
          if (!first) {
            sb.append(',');
          } else {
            first = false;
          }
          sb.append(jsonEncode(u));
        }
      }
      sb.append("\"");
      sb.append(",\"req\":\"").append(item.required).append("\"");
      sb.append(",\"maxvalue\":\"").append(item.maxValue).append("\"");
      sb.append(",\"minvalue\":\"").append(item.minValue).append("\"");
      //noinspection SpellCheckingInspection
      sb.append(",\"maskerr\":\"").append(jsonEncode(item.maskError)).append("\"");
      sb.append(",\"related\":\"").append(jsonEncode(item.related)).append("\"");
      String s = item.getProperties();
      if (s != null && !s.isEmpty()) {
        sb.append(",").append(s);
      }
      sb.append("}}");
    }
    sb.append("}");
    return sb.toString();
  }

  /**
   * Resolves the error message for an item using the item's type as the
   * error-message key.
   *
   * @param item   the item whose error message is needed
   * @param req    the current servlet request
   * @param shield the shield that owns the item
   * @return the resolved, possibly item-modified, error message
   */
  static String getErrorMessage(Item item, ServletRequest req, Shield shield) {
    return getErrorMessage(item, req, shield, null);
  }

  /**
   * Resolves the error message for an item.
   *
   * <p>Resolution order:
   * <ol>
   *   <li>Item-level custom message ({@code item.msg})</li>
   *   <li>Shield-level message for the given key</li>
   *   <li>Global message for the given key</li>
   *   <li>Item's default error message</li>
   * </ol>
   *
   * @param item        the item whose error message is needed
   * @param req         the current servlet request
   * @param shield      the shield that owns the item
   * @param errorMsgKey the message key to look up; if {@code null}, the item's
   *                    type name is used
   * @return the resolved, possibly item-modified, error message
   */
  static String getErrorMessage(Item item, ServletRequest req, Shield shield, String errorMsgKey) {
    String err = null;
    if (item.msg != null && !item.msg.isEmpty()) {
      err = item.msg;
    }
    if (err == null) {
      if (errorMsgKey == null) {
        errorMsgKey = item.getType().toString();
      }
      err = shield.errorMessages.get(errorMsgKey);
      if (err == null || err.isEmpty()) {
        Sanwaf.SanwafConfig c = shield.sanwaf.config;
        if (c != null) {
          err = c.globalErrorMessages.get(errorMsgKey);
        }
      }
    }
    if (err == null || err.isEmpty()) {
      err = item.getDefaultErrorMessage();
    }
    return item.modifyErrorMsg(req, err);
  }

  /**
   * Substitutes min/max placeholders in an invalid-length error message.
   *
   * @param errorMsg the error message template containing placeholders
   * @param min      the minimum allowed length
   * @param max      the maximum allowed length
   * @return the message with placeholders replaced by actual values
   */
  static String modifyInvalidLengthErrorMsg(String errorMsg, int min, int max) {
    int i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER1);
    if (i >= 0) {
      int pLen = ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length();
      errorMsg = errorMsg.substring(0, i) + min + errorMsg.substring(i + pLen);
    }
    i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER2);
    if (i >= 0) {
      int pLen = ItemFactory.XML_ERROR_MSG_PLACEHOLDER2.length();
      errorMsg = errorMsg.substring(0, i) + max + errorMsg.substring(i + pLen);
    }
    return errorMsg;
  }

  /**
   * JSON-encodes a string by escaping special and control characters.
   *
   * @param s the string to encode; may be {@code null}
   * @return the encoded string, or an empty string if {@code s} is {@code null}
   */
  static String jsonEncode(String s) {
    if (s == null) {
      return "";
    }
    return jsonEncodeLen(s, s.length());
  }

  /**
   * JSON-encodes {@code s}, truncated to 100 chars to avoid logging excessive
   * user input.
   */
  static String jsonEncodeTruncated(String s) {
    if (s == null) {
      return "";
    }
    return jsonEncodeLen(s, Math.min(s.length(), 100));
  }

  /**
   * JSON-encodes up to {@code len} characters of the given string.
   *
   * <p>Escapes backslash, double-quote, forward-slash, common whitespace
   * escapes, ASCII control characters (as {@code \\u00xx}), and Unicode
   * line/paragraph separators.
   *
   * @param s   the string to encode
   * @param len the number of characters to process (must not exceed
   *            {@code s.length()})
   * @return the JSON-safe encoded string
   */
  private static String jsonEncodeLen(String s, int len) {
    StringBuilder sb = null;
    for (int i = 0; i < len; i++) {
      char c = s.charAt(i);
      String esc;
      switch (c) {
      case '\\':
        esc = "\\\\";
        break;
      case '"':
        esc = "\\\"";
        break;
      case '/':
        esc = "\\/";
        break;
      case '\n':
        esc = "\\n";
        break;
      case '\r':
        esc = "\\r";
        break;
      case '\t':
        esc = "\\t";
        break;
      case '\b':
        esc = "\\b";
        break;
      case '\f':
        esc = "\\f";
        break;
      default:
        if (c < 0x20) {
          esc = CTRL_UNICODE_ESCAPES[c];
        } else if (c == '\u2028') {
          esc = "\\u2028";
        } else if (c == '\u2029') {
          esc = "\\u2029";
        } else {
          esc = null;
        }
        break;
      }
      if (esc != null) {
        if (sb == null) {
          sb = new StringBuilder(len + 16);
          sb.append(s, 0, i);
        }
        sb.append(esc);
      } else if (sb != null) {
        sb.append(c);
      }
    }
    if (sb != null) {
      return sb.toString();
    }
    return len == s.length() ? s : s.substring(0, len);
  }
}
