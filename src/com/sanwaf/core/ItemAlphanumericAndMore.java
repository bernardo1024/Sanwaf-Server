package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
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

  char[] moreChars = new char[0];
  private String moreCharsDisplay;
  private boolean[] asciiLookup = new boolean[128];
  private Set<Character> nonAsciiSet = new HashSet<>();

  ItemAlphanumericAndMore(ItemData id)
  {
    super(id);
    setMoreChars(id.type);
  }

  @Override
  List<Point> getErrorPoints(final Shield shield, final String value)
  {
    List<Point> points = new ArrayList<>();
    if (value == null || !maskError.isEmpty())
    {
      return points;
    }
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
    ModeError me = isModeError(req, value);
    if (me != null)
    {
      //return returnBasedOnDoAllBlocks(handleMode(me.error, value, req, mode, log), doAllBlocks);
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
    int i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER1);
    if (i >= 0)
    {
      return errorMsg.substring(0, i) + moreCharsDisplay + errorMsg.substring(i + ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length());
    }
    return errorMsg;
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
    int i = s.indexOf(from);
    if (i >= 0)
    {
      s = s.substring(0, i) + to + s.substring(i + from.length());
    }
    return s;
  }

  private void setMoreChars(String value)
  {
    int start = value.indexOf(ItemFactory.SEP_START);
    int end = value.lastIndexOf(ItemFactory.SEP_END);
    moreChars = getMoreCharArray(value.substring(start + ItemFactory.SEP_START.length(), end));
    asciiLookup = new boolean[128];
    nonAsciiSet = new HashSet<>();
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
    moreCharsDisplay = Metadata.jsonEncode(handleSpecialChars(moreChars));
  }

  @Override
  String getProperties()
  {
    return "\"morechars\":\"" + Metadata.jsonEncode(new String(moreChars)) + "\"";
  }

  @Override
  Types getType()
  {
    return Types.ALPHANUMERIC_AND_MORE;
  }
}

