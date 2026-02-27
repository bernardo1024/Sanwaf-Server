package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

class ItemAlphanumeric extends Item
{
  static final String INVALID_AN = "Invalid Alphanumeric: ";

  ItemAlphanumeric(ItemData id)
  {
    super(id);
  }

  @Override
  List<Point> getErrorPoints(Shield shield, final String value)
  {
    if (!maskError.isEmpty())
    {
      return Collections.emptyList();
    }
    List<Point> points = new ArrayList<>();
    int start = -1;
    int len = value.length();
    for (int i = 0; i < len; i++)
    {
      if (isNotAlphanumeric(value.charAt(i)))
      {
        if (start < 0)
        {
          start = i;
        }
      }
      else
      {
        if (start >= 0)
        {
          points.add(new Point(start, i));
          start = -1;
        }
      }
    }
    if (start >= 0)
    {
      points.add(new Point(start, len));
    }
    return points;
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (shouldSkipValidation(req, value))
    {
      return true;
    }
    for (int i = 0; i < value.length(); i++)
    {
      if (isNotAlphanumeric(value.charAt(i)))
      {
        return true;
      }
    }
    return false;
  }

  static boolean isNotAlphanumeric(char c)
  {
    return (c < 0x30 || (c >= 0x3a && c <= 0x40) || (c > 0x5a && c <= 0x60) || c > 0x7a);
  }

  @Override
  String getDefaultErrorMessage()
  {
    return INVALID_AN;
  }

  @Override
  Types getType()
  {
    return Types.ALPHANUMERIC;
  }
}

