package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class ItemConstant extends Item
{
  static final String INVALID_CONSTANT = "Invalid Constant: ";
  final Set<String> constants;

  ItemConstant(ItemData id)
  {
    super(id);
    this.constants = parseConstants(id.type);
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (shouldSkipValidation(req, value))
    {
      return true;
    }
    return value != null && !value.isEmpty() && !constants.contains(value);
  }

  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg)
  {
    int i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER1);
    if (i >= 0)
    {
      return errorMsg.substring(0, i) + Metadata.jsonEncode(constants.toString()) + errorMsg.substring(i + ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length());
    }
    return errorMsg;
  }

  @Override
  List<Point> getErrorPoints(Shield shield, String value)
  {
    if (!maskError.isEmpty())
    {
      return Collections.emptyList();
    }
    List<Point> points = new ArrayList<>();
    points.add(new Point(0, value.length()));
    return points;
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
      sb.append(Metadata.jsonEncode(s + " "));
    }
    sb.append("\"");
    return sb.toString();
  }

  @Override
  Types getType()
  {
    return Types.CONSTANT;
  }
}

