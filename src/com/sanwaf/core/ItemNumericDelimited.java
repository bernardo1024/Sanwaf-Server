package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.List;

final class ItemNumericDelimited extends ItemNumeric
{
  String delimiter = "";

  ItemNumericDelimited(ItemData id, boolean isInt)
  {
    super(id, isInt);
    setDelimiter(id.type);
  }

  @Override
  List<Point> getErrorPoints(final Shield shield, final String value)
  {
    List<Point> points = new ArrayList<>();
    if (!maskError.isEmpty())
    {
      return points;
    }

    if (value != null)
    {
      String[] ns = value.split(delimiter, -1);
      for (String n : ns)
      {
        if (!n.isEmpty())
        {
          points.addAll(super.getErrorPoints(shield, n));
        }
      }
    }
    return points;
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (mode == Modes.DISABLED)
    {
      return false;
    }
    String[] ns = value.split(delimiter);
    for (String n : ns)
    {
      if (super.inError(req, shield, n, doAllBlocks, log))
      {
        return true;
      }
    }
    return false;
  }

  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg)
  {
    int i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER1);
    if (i >= 0)
    {
      return errorMsg.substring(0, i) + Metadata.jsonEncode(delimiter) + errorMsg.substring(i + ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length(), errorMsg.length());
    }
    return errorMsg;
  }

  private void setDelimiter(String value)
  {
    int start = value.indexOf(ItemFactory.SEP_START);
    int end = value.lastIndexOf(ItemFactory.SEP_END);
    delimiter = value.substring(start + ItemFactory.SEP_START.length(), end);
  }

  @Override
  String getProperties()
  {
    return "\"delimiter\":\"" + Metadata.jsonEncode(delimiter) + "\"";
  }

  @Override
  Types getType()
  {
    return Types.NUMERIC_DELIMITED;
  }
}

