package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class ItemAlphanumericAndMore extends ItemAlphanumeric
{
  static final String INVALID_AN_MORE = "Invalid Alphanumeric And More: ";
  static final String SPACE = "\\s";
  static final String TAB = "\\t";
  static final String NEWLINE = "\\n";
  static final String CARRIAGE_RETURN = "\\r";
  static final String SPACE_LONG = "<space>";
  static final String TAB_LONG = "<tab>";
  static final String NEWLINE_LONG = "<newline>";
  static final String CARRIAGE_RETURN_LONG = "<carriage return>";

  final char[] moreChars;
  private final String moreCharsDisplay;
  private final boolean[] asciiLookup;
  private final Set<Character> nonAsciiSet;

  ItemAlphanumericAndMore(ItemData id)
  {
    super(id);
    int start = id.type.indexOf(ItemFactory.SEP_START);
    int end = id.type.lastIndexOf(ItemFactory.SEP_END);
    this.moreChars = getMoreCharArray(id.type.substring(start + ItemFactory.SEP_START.length(), end));
    this.asciiLookup = new boolean[128];
    this.nonAsciiSet = new HashSet<>();
    for (char c : moreChars)
    {
      if (c < 128)
      {
        asciiLookup[c] = true;
      }
      else
      {
        nonAsciiSet.add(c);
      }
    }
    this.moreCharsDisplay = Metadata.jsonEncode(handleSpecialChars(moreChars));
  }

  @Override
  List<Point> getErrorPoints(final Shield shield, final String value)
  {
    if (value == null || !maskError.isEmpty())
    {
      return Collections.emptyList();
    }
    List<Point> points = new ArrayList<>();
    int start = -1;
    int len = value.length();
    for (int i = 0; i < len; i++)
    {
      char c = value.charAt(i);
      if (isNotAlphanumeric(c))
      {
        start = processNotAlphanumeric(points, start, i, c);
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

  private int processNotAlphanumeric(List<Point> points, int start, int i, char c)
  {
    if (notInMoreChars(c))
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
    return start;
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
      char c = value.charAt(i);
      if (isNotAlphanumeric(c) && notInMoreChars(c))
      {
        return true;
      }
    }
    return false;
  }

  private boolean notInMoreChars(char c)
  {
    if (c < 128)
    {
      return !asciiLookup[c];
    }
    return !nonAsciiSet.contains(c);
  }

  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg)
  {
    return replacePlaceholder(errorMsg, moreCharsDisplay);
  }

  static String handleSpecialChars(char[] chars)
  {
    String s = String.valueOf(chars);
    s = replaceString(s, " ", SPACE_LONG);
    s = replaceString(s, "\t", TAB_LONG);
    s = replaceString(s, "\n", NEWLINE_LONG);
    s = replaceString(s, "\r", CARRIAGE_RETURN_LONG);
    return s;
  }

  static char[] getMoreCharArray(String s)
  {
    s = replaceString(s, SPACE, " ");
    s = replaceString(s, TAB, "\t");
    s = replaceString(s, NEWLINE, "\n");
    s = replaceString(s, CARRIAGE_RETURN, "\r");
    return s.toCharArray();
  }

  static String replaceString(String s, String from, String to)
  {
    return s.replace(from, to);
  }

  @Override
  String getProperties()
  {
    return "\"morechars\":\"" + Metadata.jsonEncode(new String(moreChars)) + "\"";
  }

  @Override
  String getDefaultErrorMessage()
  {
    return INVALID_AN_MORE;
  }

  @Override
  Types getType()
  {
    return Types.ALPHANUMERIC_AND_MORE;
  }
}

