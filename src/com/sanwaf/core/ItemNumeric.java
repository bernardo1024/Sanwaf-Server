package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

class ItemNumeric extends Item
{
  static final String INVALID_NUMBER = "Invalid Number";
  final boolean isInt;

  ItemNumeric(ItemData id, boolean isInt)
  {
    super(id);
    this.isInt = isInt;
  }

  @Override
  List<Point> getErrorPoints(final Shield shield, final String value)
  {
    if (!maskError.isEmpty())
    {
      return Collections.emptyList();
    }
    List<Point> points = new ArrayList<>();
    char[] chars = value.toCharArray();
    final int len = chars.length;
    int errStart = -1;
    boolean foundDot = false;
    int start = 0;
    if (len > 0 && chars[0] == '-')
    {
      start = 1;
    }

    for (int i = start; i < len; i++)
    {
      char c = chars[i];
      int d = c - '0';
      if (d < 0 || d > 9)
      {
        if (!isInt && !foundDot && c == '.')
        {
          foundDot = true;
        }
        else
        {
          errStart = checkErrStart(errStart, i);
        }
      }
      else
      {
        errStart = checkToAddPoint(points, errStart, i);
      }
    }
    if (errStart >= 0)
    {
      points.add(new Point(errStart, len));
    }
    return points;
  }

  private int checkToAddPoint(List<Point> points, int errStart, int i)
  {
    if (errStart >= 0)
    {
      points.add(new Point(errStart, i));
      errStart = -1;
    }
    return errStart;
  }

  private int checkErrStart(int errStart, int i)
  {
    if (errStart < 0)
    {
      errStart = i;
    }
    return errStart;
  }

  private boolean isMaxMinValueError(String value)
  {
    if (value.isEmpty() && !required)
    {
      return false;
    }
    try
    {
      double d = Double.parseDouble(value);
      if (d > maxValue || d < minValue)
      {
        return true;
      }
    }
    catch (NumberFormatException nfe)
    {
      return true;
    }
    return false;
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (shouldSkipValidation(req, value))
    {
      return true;
    }
    boolean foundDot = false;
    final int len = value.length();
    for (int i = 0; i < len; i++)
    {
      char c = value.charAt(i);
      int d = c - '0';
      if (d < 0 || d > 9)
      {
        if (!(i == 0 && c == '-' && len > 1))
        {
          if (!isInt && c == '.' && !foundDot)
          {
            foundDot = true;
          }
          else
          {
            return true;
          }
        }
      }
    }
    return isMaxMinValueError(value);
  }

  boolean inErrorRange(final String value, int from, int to)
  {
    int segLen = to - from;
    if (!required && segLen == 0)
    {
      return false;
    }
    if (segLen < min || segLen > max)
    {
      return true;
    }
    boolean foundDot = false;
    for (int i = from; i < to; i++)
    {
      char c = value.charAt(i);
      int d = c - '0';
      if (d < 0 || d > 9)
      {
        if (!(i == from && c == '-' && segLen > 1))
        {
          if (!isInt && c == '.' && !foundDot)
          {
            foundDot = true;
          }
          else
          {
            return true;
          }
        }
      }
    }
    return isMaxMinValueErrorRange(value, from, to);
  }

  private boolean isMaxMinValueErrorRange(String value, int from, int to)
  {
    if ((to - from) == 0 && !required)
    {
      return false;
    }
    try
    {
      if (isInt)
      {
        int digitCount = to - from;
        if (from < to && value.charAt(from) == '-')
        {
          digitCount--;
        }
        if (digitCount <= 15)
        {
          long v = parseLongRange(value, from, to);
          return v > maxValue || v < minValue;
        }
      }
      double d = Double.parseDouble(value.substring(from, to));
      return d > maxValue || d < minValue;
    }
    catch (NumberFormatException nfe)
    {
      return true;
    }
  }

  private static long parseLongRange(String s, int from, int to)
  {
    int i = from;
    boolean negative = false;
    if (s.charAt(i) == '-')
    {
      negative = true;
      i++;
    }
    long result = 0;
    for (; i < to; i++)
    {
      result = result * 10 + (s.charAt(i) - '0');
    }
    return negative ? -result : result;
  }

  @Override
  String getDefaultErrorMessage()
  {
    return INVALID_NUMBER;
  }

  @Override
  Types getType()
  {
    return Types.NUMERIC;
  }
}

