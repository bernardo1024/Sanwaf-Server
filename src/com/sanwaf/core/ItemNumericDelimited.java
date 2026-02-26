package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

final class ItemNumericDelimited extends ItemNumeric
{
  final String delimiter;
  final Pattern delimiterPattern;

  ItemNumericDelimited(ItemData id, boolean isInt)
  {
    super(id, isInt);
    int start = id.type.indexOf(ItemFactory.SEP_START);
    int end = id.type.lastIndexOf(ItemFactory.SEP_END);
    this.delimiter = id.type.substring(start + ItemFactory.SEP_START.length(), end);
    this.delimiterPattern = Pattern.compile(delimiter);
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
      String[] ns = delimiterPattern.split(value, -1);
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
    if (mode == Modes.DISABLED || value == null)
    {
      return false;
    }
    String[] ns = delimiterPattern.split(value);
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

