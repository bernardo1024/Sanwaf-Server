package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class ItemConstant extends Item
{
  static final String INVALID_CONSTANT = "Invalid Constant: ";
  List<String> constants = null;

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
    if (value != null && value.length() > 0 && !constants.contains(value))
    {
      return true;
    }
    return false;
  }

  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg)
  {
    int i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER1);
    if (i >= 0)
    {
      return errorMsg.substring(0, i) + Metadata.jsonEncode(constants.toString()) + errorMsg.substring(i + ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length(), errorMsg.length());
    }
    return errorMsg;
  }

  @Override
  List<Point> getErrorPoints(Shield shield, String value)
  {
    List<Point> points = new ArrayList<>();
    if (maskError.length() > 0)
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
      constants = new ArrayList<>(Arrays.asList(s.split(",")));
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

