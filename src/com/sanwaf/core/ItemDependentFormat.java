package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Validates input values using a format that depends on the value of another
 * request parameter.
 *
 * <p>The type string specifies a dependent element name followed by a set of
 * value-to-format mappings. At validation time, the value of the dependent
 * element is read from the request, and the corresponding {@link ItemFormat}
 * is used to validate the current parameter.
 *
 * <p>Configuration syntax:
 * {@code df{elementName:value1=format1;value2=format2;...}}
 *
 * <p>If the dependent element is absent from the request, or its value does
 * not match any configured key, the item passes validation.
 */
final class ItemDependentFormat extends Item {
  /** Default error message prefix for dependent-format validation failures. */
  static final String INVALID_DEP_FORMAT = "Invalid Dependent Format: ";
  /** The raw dependent-format specification string. */
  final String depFormatString;
  /** The name of the request parameter whose value selects the format. */
  final String dependentElementName;
  /** Maps dependent-element values to their corresponding format validators. */
  final Map<String, ItemFormat> formats = new HashMap<>();

  /**
   * Constructs a dependent-format item by parsing the type string into a
   * dependent element name and a map of value-to-format entries.
   *
   * @param id item configuration data containing the dependent-format type string
   */
  ItemDependentFormat(ItemData id) {
    super(id);
    String depFmt = null;
    String depName = null;
    int start = id.type.indexOf(ItemFactory.DEPENDENT_FORMAT);
    if (start >= 0) {
      depFmt = id.type.substring(start + ItemFactory.DEPENDENT_FORMAT.length(), id.type.length() - 1);
      if (!depFmt.isEmpty()) {
        String[] elementFormatData = depFmt.split(":");
        if (elementFormatData.length == 2) {
          depName = elementFormatData[0];
          String[] valueFormatPairs = elementFormatData[1].split(";");
          if (valueFormatPairs.length > 0) {
            parseFormats(id, valueFormatPairs);
          }
        }
      }
    }
    this.depFormatString = depFmt;
    this.dependentElementName = depName;
  }

  /**
   * Returns error highlight points spanning the entire value.
   *
   * @param shield the active shield (unused)
   * @param value  the input value being validated
   * @return a single-element list covering the full value, or empty if the
   *         value is empty or error masking is active
   */
  @Override
  List<Point> getErrorPoints(final Shield shield, final String value) {
    if (value.isEmpty() || !maskError.isEmpty()) {
      return Collections.emptyList();
    }
    return Collections.singletonList(new Point(0, value.length()));
  }

  /**
   * Validates the input value by looking up the format that corresponds to
   * the dependent element's current value in the request.
   *
   * <p>Returns {@code false} (no error) if the item is disabled, the
   * dependent element is not present in the request, or no format is
   * mapped to the dependent element's value.
   *
   * @param req         the servlet request (used to read the dependent element)
   * @param shield      the active shield
   * @param value       the input value to validate
   * @param doAllBlocks whether to process all detection blocks
   * @param log         whether to log violations
   * @return {@code true} if the value fails the selected format validation
   */
  @Override
  boolean inError(final ServletRequest req, Shield shield, final String value, boolean doAllBlocks, boolean log) {
    if (mode == Modes.DISABLED) {
      return false;
    }
    String elementValue = null;
    if (dependentElementName != null) {
      elementValue = req.getParameter(dependentElementName);
    }
    if (elementValue == null) {
      return false;
    }
    ItemFormat format = getFormatForValue(elementValue);

    return format != null && format.inError(req, shield, value, doAllBlocks, log);
  }

  /**
   * Looks up the format validator mapped to the given dependent-element value.
   *
   * @param value the dependent element's value
   * @return the corresponding {@link ItemFormat}, or {@code null} if none is mapped
   */
  private ItemFormat getFormatForValue(String value) {
    return formats.get(value);
  }

  /**
   * Inserts the JSON-encoded format string for the current dependent-element
   * value into the error message placeholder. Falls back to {@code " --- "}
   * if no matching format is found.
   *
   * @param req      the servlet request (used to read the dependent element)
   * @param errorMsg the error message template containing a placeholder
   * @return the error message with the format string substituted in,
   *         or an empty string if the request or dependent element name is null
   */
  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg) {
    if (req == null || dependentElementName == null) {
      return "";
    }
    String elementValue = req.getParameter(dependentElementName);
    ItemFormat format = getFormatForValue(elementValue);
    String formatString = " --- ";
    if (format != null) {
      formatString = format.formatString;
    }
    return replacePlaceholder(errorMsg, JsonFormatter.jsonEncode(formatString));
  }

  /**
   * Parses value=format pairs and creates an {@link ItemFormat} for each,
   * storing them in the {@link #formats} map keyed by the dependent value.
   *
   * @param id               the original item data (used as a template for
   *                         constructing each {@link ItemFormat})
   * @param valueFormatPairs array of strings in {@code "value=format"} form
   */
  private void parseFormats(ItemData id, String[] valueFormatPairs) {
    for (String valueFormatPair : valueFormatPairs) {
      String[] kv = valueFormatPair.split("=");
      if (kv.length == 2) {
        ItemData formatId = new ItemData(id.shield, id.name, id.mode, id.display, "f{" + kv[1] + "}", id.msg, id.uri, id.max, id.min, id.logger, id.required, id.maxValue, id.minValue, id.maskError,
            id.related, id.relatedBlocks);
        ItemFormat item = new ItemFormat(formatId);
        formats.put(kv[0], item);
      }
    }
  }

  /**
   * Returns a JSON fragment listing all configured value-to-format mappings.
   *
   * @return JSON object string with key/value pairs for each mapping
   */
  @Override
  String getProperties() {
    StringBuilder sb = new StringBuilder();
    sb.append("\"formats\":{");
    String sep = "";
    for (Map.Entry<String, ItemFormat> entry : formats.entrySet()) {
      sb.append(sep).append("\"key\":\"").append(entry.getKey()).append("\"");
      sb.append(",\"value\":\"").append(entry.getValue().formatString).append("\"");
      sep = ",";
    }
    sb.append("}");
    return sb.toString();
  }

  /** {@inheritDoc} */
  @Override
  String getDefaultErrorMessage() {
    return INVALID_DEP_FORMAT;
  }

  /** {@inheritDoc} */
  @Override
  Types getType() {
    return Types.DEPENDENT_FORMAT;
  }
}
