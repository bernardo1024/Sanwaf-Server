package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Arrays;

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
  private final char[] nonAsciiChars;

  ItemAlphanumericAndMore(ItemData id)
  {
    super(id);
    int start = id.type.indexOf(ItemFactory.SEP_START);
    int end = id.type.lastIndexOf(ItemFactory.SEP_END);
    this.moreChars = getMoreCharArray(id.type.substring(start + ItemFactory.SEP_START.length(), end));
    this.asciiLookup = new boolean[128];
    int nonAsciiCount = 0;
    for (char c : moreChars)
    {
      if (c < 128)
      {
        asciiLookup[c] = true;
      }
      else
      {
        nonAsciiCount++;
      }
    }
    char[] nac = new char[nonAsciiCount];
    int idx = 0;
    for (char c : moreChars)
    {
      if (c >= 128)
      {
        nac[idx++] = c;
      }
    }
    Arrays.sort(nac);
    this.nonAsciiChars = nac;
    this.moreCharsDisplay = JsonFormatter.jsonEncode(handleSpecialChars(moreChars));
  }

  @Override
  boolean isInvalidChar(char c)
  {
    return isNotAlphanumeric(c) && notInMoreChars(c);
  }

  private boolean notInMoreChars(char c)
  {
    if (c < 128)
    {
      return !asciiLookup[c];
    }
    return Arrays.binarySearch(nonAsciiChars, c) < 0;
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
    return "\"morechars\":\"" + JsonFormatter.jsonEncode(new String(moreChars)) + "\"";
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

