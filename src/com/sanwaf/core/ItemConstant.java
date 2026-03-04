package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class ItemConstant extends Item
{
  static final String INVALID_CONSTANT = "Invalid Constant: ";
  final Set<String> constants;
  private final String constantsDisplay;

  ItemConstant(ItemData id)
  {
    super(id);
    this.constants = parseConstants(id.type);
    this.constantsDisplay = JsonFormatter.jsonEncode(constants.toString());
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (hasPreValidationError(req, value))
    {
      return true;
    }
    return value != null && !value.isEmpty() && !constants.contains(value);
  }

  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg)
  {
    return replacePlaceholder(errorMsg, constantsDisplay);
  }

  @Override
  List<Point> getErrorPoints(Shield shield, String value)
  {
    if (!maskError.isEmpty())
    {
      return Collections.emptyList();
    }
    return Collections.singletonList(new Point(0, value.length()));
  }

  private static Set<String> parseConstants(String value)
  {
    int start = value.indexOf(ItemFactory.CONSTANT);
    if (start >= 0)
    {
      String s = value.substring(start + ItemFactory.CONSTANT.length(), value.length() - 1);
      String[] parts = s.split(",");
      Set<String> result = new LinkedHashSet<>(parts.length * 2);
      result.addAll(Arrays.asList(parts));
      return result;
    }
    return Collections.emptySet();
  }

  @Override
  String getProperties()
  {
    StringBuilder sb = new StringBuilder();
    sb.append("\"constant\":\"");
    for (String s : constants)
    {
      sb.append(JsonFormatter.jsonEncode(s)).append(' ');
    }
    sb.append("\"");
    return sb.toString();
  }

  @Override
  String getDefaultErrorMessage()
  {
    return INVALID_CONSTANT;
  }

  @Override
  Types getType()
  {
    return Types.CONSTANT;
  }
}

