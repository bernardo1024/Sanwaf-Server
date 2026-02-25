package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

final class ItemFormat extends Item
{
  static final String INVALID_FORMAT = "Invalid Format: ";
  private static final int ACCEPT_VALUE = Integer.MAX_VALUE;
  private static final PlaceholderBlock PLACEHOLDER = new PlaceholderBlock();
  private static final CharClassBlock ANY_CHAR = new CharClassBlock('x');
  private static final CharClassBlock DIGIT = new CharClassBlock('#');
  private static final CharClassBlock UPPER = new CharClassBlock('A');
  private static final CharClassBlock LOWER = new CharClassBlock('a');
  private static final CharClassBlock LETTER = new CharClassBlock('c');
  String formatString = null;
  private boolean hasDateVariables;
  final List<List<FmtBlock>> formatsBlocks = new ArrayList<>();

  ItemFormat(ItemData id)
  {
    super(id);
    setFormat(id.type);
  }

  @Override
  List<Point> getErrorPoints(final Shield shield, final String value)
  {
    List<Point> points = new ArrayList<>();
    if (value.isEmpty() || !maskError.isEmpty())
    {
      return points;
    }
    points.add(new Point(0, value.length()));
    return points;
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (mode == Modes.DISABLED)
    {
      return false;
    }
    if (formatsBlocks.isEmpty())
    {
      return false;
    }
    if (!required && value.isEmpty())
    {
      return false;
    }
    boolean foundValidFormat = false;
    for (List<FmtBlock> formatBlocks : formatsBlocks)
    {
      if (!formatInError(value, formatBlocks))
      {
        foundValidFormat = true;
        break;
      }
    }

    return !foundValidFormat;
  }

  private boolean formatInError(final String value, List<FmtBlock> formatBlocks)
  {
    if (formatBlocks.isEmpty())
    {
      return false;
    }

    int formatlen = formatBlocks.size();
    if (!hasDateVariables && value.length() != formatlen)
    {
      return true;
    }

    Calendar cal = null;
    if (hasDateVariables)
    {
      cal = Calendar.getInstance();
    }

    for (int i = 0; i < value.length(); i++)
    {
      if (i >= formatBlocks.size())
      {
        return true;
      }
      FmtBlock block = formatBlocks.get(i);
      int advance = block.match(value, i, cal);
      if (advance == ACCEPT_VALUE)
      {
        return false;
      }
      if (advance < 0)
      {
        return true;
      }
      i += advance;
    }
    return false;
  }

  private static String resolveDateVariables(String format, Calendar cal)
  {
    String newMdy = "";
    String parsedValue = format;
    String[] dateOrder = { "dd", "mm", "yyyy", "yy" };

    for (String s : dateOrder)
    {
      int last;
      while (true)
      {
        int startMdyReplacePos;
        int endMdyReplacePos;
        last = parsedValue.indexOf(s);
        if (last < 0)
        {
          break;
        }
        startMdyReplacePos = last;
        endMdyReplacePos = last + s.length();

        switch (s)
        {
        case "yy":
        {
          int year = cal.get(Calendar.YEAR);
          newMdy = String.valueOf(year).substring(2);
          last += 2;
          newMdy = adjustDate(parsedValue, last, newMdy);
          break;
        }
        case "yyyy":
        {
          int year = cal.get(Calendar.YEAR);
          newMdy = String.valueOf(year);
          last += 4;
          newMdy = adjustDate(parsedValue, last, newMdy);
          break;
        }
        case "mm":
          int month = cal.get(Calendar.MONTH);
          newMdy = String.valueOf(month + 1);
          last += 2;
          newMdy = adjustDate(parsedValue, last, newMdy);
          if (Integer.parseInt(newMdy) > 12)
          {
            newMdy = "12";
          }
          break;
        case "dd":
          int day = cal.get(Calendar.DAY_OF_MONTH);
          newMdy = String.valueOf(day);
          last += 2;
          newMdy = adjustDate(parsedValue, last, newMdy);
          if (Integer.parseInt(newMdy) > 31)
          {
            newMdy = "31";
          }
          break;
        }

        if (parsedValue.charAt(last) == '(')
        {
          int endOfNum = parsedValue.indexOf(')', last);
          parsedValue = parsedValue.substring(0, startMdyReplacePos) + newMdy + parsedValue.substring(endOfNum + 1);
        }
        else
        {
          parsedValue = parsedValue.substring(0, startMdyReplacePos) + newMdy + parsedValue.substring(endMdyReplacePos);
        }
      }
    }
    return parsedValue;
  }

  private static String adjustDate(String parsedValue, int last, String newMdy)
  {
    int newValue = Integer.parseInt(newMdy);
    if (parsedValue.charAt(last) == '(')
    {
      int endOfNum = parsedValue.indexOf(')', last);
      String num = parsedValue.substring(last + 2, endOfNum);
      int parsedNum = Integer.parseInt(num);
      char arith = parsedValue.charAt(last + 1);
      switch (arith)
      {
      case '+':
        newValue += parsedNum;
        break;
      case '-':
        newValue -= parsedNum;
        break;
      }
    }
    return String.valueOf(newValue);
  }

  private static String escapeChars(String s)
  {
    char[] src = s.toCharArray();
    char[] dst = new char[src.length];
    int d = 0;
    for (int i = 0; i < src.length; i++)
    {
      if (src[i] == '\\' && i + 1 < src.length)
      {
        char next = src[i + 1];
        char replacement;
        switch (next)
        {
        case '#':
          replacement = '\t';
          break;
        case 'A':
          replacement = '\n';
          break;
        case 'a':
          replacement = '\r';
          break;
        case 'c':
          replacement = '\f';
          break;
        case '[':
          replacement = '\b';
          break;
        case ']':
          replacement = '\0';
          break;
        case '|':
          replacement = '\1';
          break;
        case 'x':
          replacement = '\2';
          break;
        case ':':
          replacement = '\3';
          break;
        case '=':
          replacement = '\4';
          break;
        case '(':
          replacement = '\5';
          break;
        case ')':
          replacement = '\6';
          break;
        case '+':
          replacement = '\7';
          break;
        case '-':
          replacement = '\016';
          break;
        case ';':
          replacement = '\017';
          break;
        default:
          dst[d++] = src[i];
          continue;
        }
        dst[d++] = replacement;
        i++;
      }
      else
      {
        dst[d++] = src[i];
      }
    }
    return new String(dst, 0, d);
  }

  private static char unEscapedChar(char c)
  {
    switch (c)
    {
    case '\t':
      return '#';
    case '\n':
      return 'A';
    case '\r':
      return 'a';
    case '\f':
      return 'c';
    case '\b':
      return '[';
    case '\0':
      return ']';
    case '\1':
      return '|';
    case '\2':
      return 'x';
    case '\3':
      return ':';
    case '\4':
      return '=';
    case '\5':
      return '(';
    case '\6':
      return ')';
    case '\7':
      return '+';
    case '\016':
      return '-';
    case '\017':
      return ';';
    default:
      return c;
    }
  }

  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg)
  {
    int i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER1);
    if (i >= 0)
    {
      return errorMsg.substring(0, i) + Metadata.jsonEncode(formatString) + errorMsg.substring(i + ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length());
    }
    return errorMsg;
  }

  private void setFormat(String value)
  {
    int start = value.indexOf(ItemFactory.FORMAT);
    if (start >= 0)
    {
      formatString = value.substring(start + ItemFactory.FORMAT.length(), value.length() - 1);
      parseFormats(formatString);
      hasDateVariables = formatString.contains("dd") || formatString.contains("mm") || formatString.contains("yy") || formatString.contains("yyyy)");
    }
  }

  private void parseFormats(String format)
  {
    if (format.isEmpty())
    {
      return;
    }
    String[] formats = format.split("\\|\\|");

    for (String thisFormat : formats)
    {
      formatsBlocks.add(parseFormat(thisFormat));
    }
  }

  private List<FmtBlock> parseFormat(String format)
  {
    List<FmtBlock> formatBlocks = new ArrayList<>();
    format = escapeChars(format);
    int last = 0;

    while (true)
    {
      int pos = format.indexOf('#', last);
      if (pos < 0)
      {
        addRemainderCharsAsBlocks(format, last, formatBlocks);
        break;
      }

      for (int k = last; k < pos; k++)
      {
        formatBlocks.add(charToBlock(format.charAt(k)));
      }

      if (pos + 1 < format.length() && format.charAt(pos + 1) == '[')
      {
        int end = format.indexOf(']', pos);
        if (end < 0)
        {
          formatBlocks.clear();
          break;
        }
        String inner = format.substring(pos + 2, end);
        last = end + 1;

        if (containsDateVariable(inner))
        {
          String rawBlock = format.substring(pos, end + 1);
          formatBlocks.add(new DateRangeBlock(rawBlock));
          int dash = inner.indexOf('-');
          if (dash >= 0)
          {
            int numDigits = inner.length() - (dash + 1);
            addPlaceholderBlocks(numDigits - 1, formatBlocks);
          }
        }
        else if (inner.contains(","))
        {
          formatBlocks.add(new CommaListBlock(inner));
        }
        else
        {
          int dash = inner.indexOf('-');
          if (dash >= 0)
          {
            String minStr = inner.substring(0, dash);
            String maxStr = inner.substring(dash + 1);
            try
            {
              int min = Integer.parseInt(minStr);
              int max = Integer.parseInt(maxStr);
              int maxLen = String.valueOf(max).length();
              formatBlocks.add(new RangeBlock(min, max, maxLen));
              addPlaceholderBlocks(maxLen - 1, formatBlocks);
            }
            catch (NumberFormatException e)
            {
              formatBlocks.clear();
              break;
            }
          }
          else
          {
            formatBlocks.clear();
            break;
          }
        }
      }
      else
      {
        formatBlocks.add(DIGIT);
        last = pos + 1;
      }
    }
    return formatBlocks;
  }

  private static void addPlaceholderBlocks(int count, List<FmtBlock> formatBlocks)
  {
    for (int i = 0; i < count; i++)
    {
      formatBlocks.add(PLACEHOLDER);
    }
  }

  private static FmtBlock charToBlock(char c)
  {
    switch (c)
    {
    case 'x':
      return ANY_CHAR;
    case '#':
      return DIGIT;
    case 'A':
      return UPPER;
    case 'a':
      return LOWER;
    case 'c':
      return LETTER;
    default:
      return new LiteralBlock(unEscapedChar(c));
    }
  }

  private static void addRemainderCharsAsBlocks(String format, int last, List<FmtBlock> formatBlocks)
  {
    for (int k = last; k < format.length(); k++)
    {
      formatBlocks.add(charToBlock(format.charAt(k)));
    }
  }

  private static boolean containsDateVariable(String s)
  {
    return s.contains("dd") || s.contains("mm") || s.contains("yy");
  }

  @Override
  String getProperties()
  {
    return "\"format\":\"" + Metadata.jsonEncode(formatString) + "\"";
  }

  @Override
  Types getType()
  {
    return Types.FORMAT;
  }

  private static abstract class FmtBlock
  {
    abstract int match(String value, int pos, Calendar cal);

    static int matchRange(String value, int pos, int min, int max, int maxLen)
    {
      int num = 0;
      for (int j = 0; j < maxLen; j++)
      {
        if (pos + j >= value.length())
        {
          break;
        }
        char ch = value.charAt(pos + j);
        if (ch < '0' || ch > '9')
        {
          return -1;
        }
        num = num * 10 + (ch - '0');
      }
      return (num >= min && num <= max) ? maxLen - 1 : -1;
    }
  }

  private static final class LiteralBlock extends FmtBlock
  {
    final char expected;

    LiteralBlock(char expected)
    {
      this.expected = expected;
    }

    int match(String value, int pos, Calendar cal)
    {
      return value.charAt(pos) == expected ? 0 : -1;
    }
  }

  private static final class CharClassBlock extends FmtBlock
  {
    final char type;

    CharClassBlock(char type)
    {
      this.type = type;
    }

    int match(String value, int pos, Calendar cal)
    {
      char c = value.charAt(pos);
      switch (type)
      {
      case 'x':
        return 0;
      case '#':
        return (c >= '0' && c <= '9') ? 0 : -1;
      case 'A':
        return (c >= 'A' && c <= 'Z') ? 0 : -1;
      case 'a':
        return (c >= 'a' && c <= 'z') ? 0 : -1;
      case 'c':
        return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) ? 0 : -1;
      default:
        return -1;
      }
    }
  }

  private static final class CommaListBlock extends FmtBlock
  {
    final boolean[] validChars = new boolean[128];

    CommaListBlock(String inner)
    {
      for (String s : inner.split(","))
      {
        if (s.length() == 1 && s.charAt(0) < 128)
        {
          validChars[s.charAt(0)] = true;
        }
      }
    }

    int match(String value, int pos, Calendar cal)
    {
      char ch = value.charAt(pos);
      return (ch < 128 && validChars[ch]) ? 0 : -1;
    }
  }

  private static final class RangeBlock extends FmtBlock
  {
    final int min;
    final int max;
    final int maxLen;

    RangeBlock(int min, int max, int maxLen)
    {
      this.min = min;
      this.max = max;
      this.maxLen = maxLen;
    }

    int match(String value, int pos, Calendar cal)
    {
      return matchRange(value, pos, min, max, maxLen);
    }
  }

  private static final class DateRangeBlock extends FmtBlock
  {
    final String rawBlock;

    DateRangeBlock(String rawBlock)
    {
      this.rawBlock = rawBlock;
    }

    int match(String value, int pos, Calendar cal)
    {
      String resolved = (cal != null) ? resolveDateVariables(rawBlock, cal) : rawBlock;
      String inner = resolved.substring(2, resolved.length() - 1);

      if (inner.contains(","))
      {
        char ch = value.charAt(pos);
        for (String s : inner.split(","))
        {
          if (s.length() == 1 && s.charAt(0) == ch)
          {
            return 0;
          }
        }
        return -1;
      }

      String[] parts = inner.split("-");
      if (parts.length != 2)
      {
        return ACCEPT_VALUE;
      }

      int minNum;
      int maxNum;
      int maxLenLocal;
      try
      {
        minNum = Integer.parseInt(parts[0]);
        maxNum = Integer.parseInt(parts[1]);
        maxLenLocal = String.valueOf(maxNum).length();
      }
      catch (NumberFormatException e)
      {
        return ACCEPT_VALUE;
      }

      return matchRange(value, pos, minNum, maxNum, maxLenLocal);
    }
  }

  private static final class PlaceholderBlock extends FmtBlock
  {
    int match(String value, int pos, Calendar cal)
    {
      return 0;
    }
  }
}
