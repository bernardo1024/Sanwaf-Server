package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
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
    List<Point> points = new ArrayList<>();
    if (!maskError.isEmpty())
    {
      return points;
    }
    int start = -1;
    char[] chars = value.toCharArray();
    int len = chars.length;
    for (int i = 0; i < len; i++)
    {
      if (isNotAlphanumeric(chars[i]))
      {
        if (start < 0)
        {
          start = i;
        }
      }
      else
      {
        if (start >= 0 || i == len - 1)
        {
          points.add(new Point(start, i));
          start = -1;
        }
      }
    }
    return points;
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    ModeError me = isModeError(req, value);
    if (me != null)
    {
      return true;
    }
    char[] chars = value.toCharArray();
    for (char aChar : chars)
    {
      if (isNotAlphanumeric(aChar))
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
  Types getType()
  {
    return Types.ALPHANUMERIC;
  }
}

