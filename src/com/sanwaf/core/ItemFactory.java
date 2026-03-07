package com.sanwaf.core;

import com.sanwaf.log.Logger;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Factory that creates {@link Item} instances from type strings parsed from XML
 * configuration.
 *
 * <p>Type strings are short codes (e.g. {@code "n"} for numeric, {@code "r{...}"}
 * for regex) that map to concrete {@link Item} subclasses. The factory also owns
 * XML element/attribute name constants and the error-message bootstrapping logic.
 *
 * <p>This class is not instantiable.
 */
public final class ItemFactory {
  /** Type code for integer validation. */
  static final String INTEGER = "i";
  /** Type code prefix for delimited integer validation. */
  static final String INTEGER_DELIMITED = "i{";
  /** Type code for numeric validation. */
  static final String NUMERIC = "n";
  /** Type code prefix for delimited numeric validation. */
  static final String NUMERIC_DELIMITED = "n{";
  /** Type code for alphanumeric validation. */
  static final String ALPHANUMERIC = "a";
  /** Type code prefix for alphanumeric-and-more validation. */
  static final String ALPHANUMERIC_AND_MORE = "a{";
  /** Type code for string (XSS-protected) validation. */
  static final String STRING = "s";
  /** Type code for open (no content validation). */
  static final String OPEN = "o";
  /** Type code for single-character validation. */
  static final String CHAR = "c";
  /** Type code prefix for named-regex validation. */
  static final String REGEX = "r{";
  /** Type code prefix for inline-regex validation. */
  static final String INLINE_REGEX = "x{";
  /** Type code prefix for Java-class validation. */
  static final String JAVA = "j{";
  /** Type code prefix for constant-value validation. */
  static final String CONSTANT = "k{";
  /** Type code prefix for format validation. */
  static final String FORMAT = "f{";
  /** Type code prefix for dependent-format validation. */
  static final String DEPENDENT_FORMAT = "d{";

  /** XML element name for the items collection. */
  static final String XML_ITEMS = "items";
  /** XML element name for a single item. */
  static final String XML_ITEM = "item";
  /** XML attribute: parameter name. */
  static final String XML_ITEM_NAME = "name";
  /** XML attribute: validation mode. */
  static final String XML_ITEM_MODE = "mode";
  /** XML attribute: match expression. */
  static final String XML_ITEM_MATCH = "match";
  /** XML attribute: display name. */
  static final String XML_ITEM_DISPLAY = "display";
  /** XML attribute: type code. */
  static final String XML_ITEM_TYPE = "type";
  /** XML attribute: maximum character length. */
  static final String XML_ITEM_MAX = "max";
  /** XML attribute: minimum character length. */
  static final String XML_ITEM_MIN = "min";
  /** XML attribute: custom error message. */
  static final String XML_ITEM_MSG = "msg";
  /** XML attribute: URI restriction. */
  static final String XML_ITEM_URI = "uri";
  /** XML attribute: required flag. */
  static final String XML_ITEM_REQUIRED = "req";
  /** XML attribute: maximum numeric value. */
  static final String XML_ITEM_MAX_VAL = "max-value";
  /** XML attribute: minimum numeric value. */
  static final String XML_ITEM_MIN_VAL = "min-value";
  /** XML attribute: related-field expression. */
  static final String XML_ITEM_RELATED = "related";
  /** XML attribute: error masking string. */
  static final String XML_ITEM_MASK_ERROR = "mask-err";

  /** Pattern matching one or more whitespace characters. */
  private static final Pattern WHITESPACE_RUN = Pattern.compile("\\s+");

  /**
   * Private constructor to prevent instantiation.
   */
  private ItemFactory() {}

  /**
   * Parses an item from XML without a shield context.
   *
   * <p>Convenience overload used for global (shield-independent) item parsing.
   *
   * @param xml    the XML element to parse
   * @param logger logger instance
   * @return a new {@link Item} matching the declared type
   */
  static Item parseItem(Xml xml, Logger logger) {
    return parseItem(null, xml, null, false, logger);
  }

  /**
   * Parses an item from XML within a shield context.
   *
   * @param shield                    owning shield
   * @param xml                       the XML element to parse
   * @param includeEndpointAttributes {@code true} to parse endpoint-level
   *                                  attributes such as related-field rules
   * @param logger                    logger instance
   * @return a new {@link Item} matching the declared type
   */
  static Item parseItem(Shield shield, Xml xml, boolean includeEndpointAttributes, com.sanwaf.log.Logger logger) {
    return parseItem(shield, xml, null, includeEndpointAttributes, logger);
  }

  /**
   * Parses an item from XML, optionally overriding the parameter name.
   *
   * <p>This is the primary parsing entry point. It reads all XML attributes,
   * normalises values, constructs an {@link ItemData}, and delegates to
   * {@link #getNewItem(ItemData)}.
   *
   * @param shield                    owning shield, or {@code null}
   * @param xml                       the XML element to parse
   * @param nameOverride              if non-{@code null}, overrides the name
   *                                  from XML
   * @param includeEndpointAttributes {@code true} to parse related-field rules
   * @param logger                    logger instance
   * @return a new {@link Item} matching the declared type
   */
  static Item parseItem(Shield shield, Xml xml, String nameOverride, boolean includeEndpointAttributes, com.sanwaf.log.Logger logger) {
    String name = nameOverride != null ? nameOverride : xml.get(XML_ITEM_NAME);
    Modes mode = Modes.getMode(xml.get(XML_ITEM_MODE), (shield != null ? shield.mode : Modes.BLOCK));
    String display = xml.get(XML_ITEM_DISPLAY);
    String type = xml.get(XML_ITEM_TYPE);
    String msg = xml.get(XML_ITEM_MSG);
    String uri = xml.get(XML_ITEM_URI);
    String sMax = xml.get(XML_ITEM_MAX);
    String sMin = xml.get(XML_ITEM_MIN);

    int max = Integer.MAX_VALUE;
    int min = 0;
    if (!sMax.isEmpty()) {
      max = Shield.parseInt(sMax, Integer.MAX_VALUE);
    }
    if (!sMin.isEmpty()) {
      min = Shield.parseInt(sMin, 0);
    }
    if (max == -1) {
      max = Integer.MAX_VALUE;
    }
    if (min == -1) {
      min = Integer.MIN_VALUE;
    }
    if (min < -1) {
      min = 0;
    }
    if (display.contains(":::")) {
      display = name;
    }
    if (type.contains("{")) {
      type = ensureComplexTypeFormat(type);
    }

    boolean required = Boolean.parseBoolean(xml.get(XML_ITEM_REQUIRED));

    double maxValue = Integer.MAX_VALUE;
    String sMaxVal = xml.get(XML_ITEM_MAX_VAL);
    if (!sMaxVal.isEmpty()) {
      maxValue = Shield.parseDouble(sMaxVal, Integer.MAX_VALUE);
    }

    double minValue = Integer.MIN_VALUE;
    String sMinVal = xml.get(XML_ITEM_MIN_VAL);
    if (!sMinVal.isEmpty()) {
      minValue = Shield.parseDouble(sMinVal, Integer.MIN_VALUE);
    }

    String maskError = xml.get(XML_ITEM_MASK_ERROR);

    String related = null;
    RelationValidator.Block[] relatedBlocks = null;
    if (includeEndpointAttributes) {
      related = removeRelatedSpace(xml.get(XML_ITEM_RELATED));
      relatedBlocks = RelationValidator.parseRelation(related);
    }

    return getNewItem(new ItemData(shield, name, mode, display, type, msg, uri, max, min, logger, required, maxValue, minValue, maskError, related, relatedBlocks));
  }

  /**
   * Normalises whitespace in a related-field expression for consistent parsing.
   *
   * @param related the raw related expression
   * @return the expression with extraneous whitespace removed
   */
  private static String removeRelatedSpace(String related) {
    related = related.trim();
    if (related.isEmpty()) {
      return related;
    }
    related = WHITESPACE_RUN.matcher(related).replaceAll(" ");
    related = related.replace(") && (", ")&&(");
    related = related.replace(" || ", "||");
    related = related.replace(" : ", ":");
    related = related.replace("( ", "(");
    related = related.replace(" )", ")");
    return related;
  }

  /**
   * Creates a concrete {@link Item} subclass from the given configuration.
   *
   * <p>The {@link ItemData#type} string is matched against known type codes
   * to select the appropriate subclass. Unknown types default to
   * {@link ItemString}.
   *
   * @param id item configuration holder
   * @return a new {@link Item} instance
   */
  static Item getNewItem(ItemData id) {
    String t = id.type.toLowerCase();
    int pos = t.indexOf(ItemFactory.SEP_START);
    if (pos > 0) {
      t = t.substring(0, pos + ItemFactory.SEP_START.length());
    }
    switch (t) {
    case NUMERIC:
      return new ItemNumeric(id, false);
    case OPEN:
      return new ItemOpen(id);
    case INTEGER:
      return new ItemNumeric(id, true);
    case ALPHANUMERIC:
      return new ItemAlphanumeric(id);
    case CHAR:
      return new ItemChar(id);
    }

    switch (t) {
    case NUMERIC_DELIMITED:
      return new ItemNumericDelimited(id, false);
    case INTEGER_DELIMITED:
      return new ItemNumericDelimited(id, true);
    case ALPHANUMERIC_AND_MORE:
      return new ItemAlphanumericAndMore(id);
    case REGEX:
    case INLINE_REGEX:
      return new ItemRegex(id);
    case JAVA:
      if (id.shield == null) {
        return new ItemString(id);
      }
      return new ItemJava(id);
    case CONSTANT:
      return new ItemConstant(id);
    case FORMAT:
      return new ItemFormat(id);
    case DEPENDENT_FORMAT:
      return new ItemDependentFormat(id);
    }
    return new ItemString(id);
  }

  /**
   * Ensures a complex type string is properly terminated with a closing brace.
   *
   * @param type the type string containing a {@code '{'} character
   * @return the type string guaranteed to end with {@code '}'}
   */
  private static String ensureComplexTypeFormat(String type) {
    if (!type.endsWith(ItemFactory.SEP_END)) {
      return type + ItemFactory.SEP_END;
    }
    return type;
  }

  /** Opening brace for complex type delimiters. */
  static final String SEP_START = "{";
  /** Closing brace for complex type delimiters. */
  static final String SEP_END = "}";
  /** XML element name for the error-messages block. */
  static final String XML_ERROR_MSG = "errorMessages";
  /** XML element name for the alphanumeric error message. */
  static final String XML_ERROR_MSG_ALPHANUMERIC = "alphanumeric";
  /** XML element name for the alphanumeric-and-more error message. */
  static final String XML_ERROR_MSG_ALPHANUMERIC_AND_MORE = "alphanumericAndMore";
  /** XML element name for the char error message. */
  static final String XML_ERROR_MSG_CHAR = "char";
  /** XML element name for the numeric error message. */
  static final String XML_ERROR_MSG_NUMERIC = "numeric";
  /** XML element name for the numeric-delimited error message. */
  static final String XML_ERROR_MSG_NUMERIC_DELIMITED = "numericDelimited";
  /** XML element name for the integer error message. */
  static final String XML_ERROR_MSG_INTEGER = "integer";
  /** XML element name for the integer-delimited error message. */
  static final String XML_ERROR_MSG_INTEGER_DELIMITED = "integerDelimited";
  /** XML element name for the string error message. */
  static final String XML_ERROR_MSG_STRING = "string";
  /** XML element name for the open error message. */
  static final String XML_ERROR_MSG_OPEN = "open";
  /** XML element name for the regex error message. */
  static final String XML_ERROR_MSG_REGEX = "regex";
  /** XML element name for the java error message. */
  static final String XML_ERROR_MSG_JAVA = "java";
  /** XML element name for the constant error message. */
  static final String XML_ERROR_MSG_CONSTANT = "constant";
  /** XML element name for the format error message. */
  static final String XML_ERROR_MSG_FORMAT = "format";
  /** XML element name for the dependent-format error message. */
  static final String XML_ERROR_MSG_DEPENDENT_FORMAT = "dependentFormat";
  /** XML element name for the invalid-length error message. */
  static final String XML_INVALID_LENGTH_MSG = "invalidLength";
  /** XML element name for the required-field error message. */
  static final String XML_REQUIRED_MSG = "required";
  /** First placeholder token ({@code {0}}) in error message templates. */
  static final String XML_ERROR_MSG_PLACEHOLDER1 = "{0}";
  /** Second placeholder token ({@code {1}}) in error message templates. */
  static final String XML_ERROR_MSG_PLACEHOLDER2 = "{1}";

  /**
   * Populates the error-message map from the {@code <errorMessages>} XML block.
   *
   * <p>Each {@link Types} constant is mapped to its corresponding message text.
   *
   * @param map       the map to populate (keyed by type name)
   * @param xmlString the XML element containing the error-messages block
   */
  static void setErrorMessages(Map<String, String> map, Xml xmlString) {
    Xml xml = new Xml(xmlString.get(XML_ERROR_MSG));
    map.put(String.valueOf(Types.ALPHANUMERIC), xml.get(XML_ERROR_MSG_ALPHANUMERIC));
    map.put(String.valueOf(Types.ALPHANUMERIC_AND_MORE), xml.get(XML_ERROR_MSG_ALPHANUMERIC_AND_MORE));
    map.put(String.valueOf(Types.CHAR), xml.get(XML_ERROR_MSG_CHAR));
    map.put(String.valueOf(Types.NUMERIC), xml.get(XML_ERROR_MSG_NUMERIC));
    map.put(String.valueOf(Types.NUMERIC_DELIMITED), xml.get(XML_ERROR_MSG_NUMERIC_DELIMITED));
    map.put(String.valueOf(Types.INTEGER), xml.get(XML_ERROR_MSG_INTEGER));
    map.put(String.valueOf(Types.INTEGER_DELIMITED), xml.get(XML_ERROR_MSG_INTEGER_DELIMITED));
    map.put(String.valueOf(Types.STRING), xml.get(XML_ERROR_MSG_STRING));
    map.put(String.valueOf(Types.OPEN), xml.get(XML_ERROR_MSG_OPEN));
    map.put(String.valueOf(Types.REGEX), xml.get(XML_ERROR_MSG_REGEX));
    map.put(String.valueOf(Types.JAVA), xml.get(XML_ERROR_MSG_JAVA));
    map.put(String.valueOf(Types.CONSTANT), xml.get(XML_ERROR_MSG_CONSTANT));
    map.put(String.valueOf(Types.FORMAT), xml.get(XML_ERROR_MSG_FORMAT));
    map.put(String.valueOf(Types.DEPENDENT_FORMAT), xml.get(XML_ERROR_MSG_DEPENDENT_FORMAT));
    map.put(XML_INVALID_LENGTH_MSG, xml.get(XML_INVALID_LENGTH_MSG));
    map.put(XML_REQUIRED_MSG, xml.get(XML_REQUIRED_MSG));
  }

}
