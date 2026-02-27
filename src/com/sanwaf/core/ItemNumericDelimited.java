package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class ItemNumericDelimited extends ItemNumeric
{
  final String delimiter;

  ItemNumericDelimited(ItemData id, boolean isInt)
  {
    super(id, isInt);
    int start = id.type.indexOf(ItemFactory.SEP_START);
    int end = id.type.lastIndexOf(ItemFactory.SEP_END);
    this.delimiter = id.type.substring(start + ItemFactory.SEP_START.length(), end);
  }

  @Override
  List<Point> getErrorPoints(final Shield shield, final String value)
  {
    if (!maskError.isEmpty() || value == null || delimiter.isEmpty())
    {
      return Collections.emptyList();
    }
    List<Point> points = new ArrayList<>();
    int start = 0;
    int pos;
    while ((pos = value.indexOf(delimiter, start)) >= 0)
    {
      if (start < pos)
      {
        super.getErrorPointsRange(value, start, pos, points);
      }
      start = pos + delimiter.length();
    }
    if (start < value.length())
    {
      super.getErrorPointsRange(value, start, value.length(), points);
    }
    return points;
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (mode == Modes.DISABLED || value == null)
    {
      return false;
    }
    if (delimiter.isEmpty())
    {
      return super.inError(req, shield, value, doAllBlocks, log);
    }
    if (isUriInvalid(req))
    {
      return true;
    }
    int start = 0;
    int pos;
    while ((pos = value.indexOf(delimiter, start)) >= 0)
    {
      if (start < pos && super.inErrorRange(value, start, pos))
      {
        return true;
      }
      start = pos + delimiter.length();
    }
    if (start < value.length())
    {
      return super.inErrorRange(value, start, value.length());
    }
    return false;
  }

  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg)
  {
    return replacePlaceholder(errorMsg, Metadata.jsonEncode(delimiter));
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

