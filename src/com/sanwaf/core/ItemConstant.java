package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class ItemConstant extends Item
{
  static final String INVALID_CONSTANT = "Invalid Constant: ";
  Set<String> constants = null;

  ItemConstant(ItemData id)
  {
    super(id);
    setConstants(id.type);
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    ModeError me = isModeError(req, value);
    if (me != null)
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
    List<Point> points = new ArrayList<>();
    if (!maskError.isEmpty())
    {
      return points;
    }
    points.add(new Point(0, value.length()));
    return points;
  }

  private void setConstants(String value)
  {
    int start = value.indexOf(ItemFactory.CONSTANT);
    if (start >= 0)
    {
      String s = value.substring(start + ItemFactory.CONSTANT.length(), value.length() - 1);
      String[] parts = s.split(",");
      constants = new LinkedHashSet<>(parts.length * 2);
      for (String part : parts)
      {
        constants.add(part);
      }
    }
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

