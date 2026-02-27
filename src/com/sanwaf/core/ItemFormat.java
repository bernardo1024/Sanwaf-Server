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
  private static final ThreadLocal<Calendar> CACHED_CAL = ThreadLocal.withInitial(Calendar::getInstance);
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

    int formatLen = formatBlocks.size();
    if (!hasDateVariables && value.length() != formatLen)
    {
      return true;
    }

    Calendar cal = null;
    if (hasDateVariables)
    {
      cal = CACHED_CAL.get();
      cal.setTimeInMillis(System.currentTimeMillis());
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
    return replacePlaceholder(errorMsg, Metadata.jsonEncode(formatString));
  }

  private void setFormat(String value)
  {
    int start = value.indexOf(ItemFactory.FORMAT);
    if (start >= 0)
    {
      formatString = value.substring(start + ItemFactory.FORMAT.length(), value.length() - 1);
      parseFormats(formatString);
      hasDateVariables = formatString.contains("dd") || formatString.contains("mm") || formatString.contains("yy");
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

  private static int numDigits(int n)
  {
    if (n < 0) n = -n;
    if (n < 10) return 1;
    if (n < 100) return 2;
    if (n < 1000) return 3;
    if (n < 10000) return 4;
    return String.valueOf(n).length();
  }

  private static int findRangeSep(String inner)
  {
    int depth = 0;
    for (int i = 0; i < inner.length(); i++)
    {
      char c = inner.charAt(i);
      if (c == '(') depth++;
      else if (c == ')') depth--;
      else if (c == '-' && depth == 0) return i;
    }
    return -1;
  }

  private static DateVal parseDateVal(String s)
  {
    int kind;
    int prefixLen;
    if (s.startsWith("yyyy"))
    {
      kind = DateVal.YEAR4;
      prefixLen = 4;
    }
    else if (s.startsWith("yy"))
    {
      kind = DateVal.YEAR2;
      prefixLen = 2;
    }
    else if (s.startsWith("mm"))
    {
      kind = DateVal.MONTH;
      prefixLen = 2;
    }
    else if (s.startsWith("dd"))
    {
      kind = DateVal.DAY;
      prefixLen = 2;
    }
    else
    {
      try
      {
        return new DateVal(DateVal.LITERAL, Integer.parseInt(s));
      }
      catch (NumberFormatException e)
      {
        return null;
      }
    }
    int adjust = 0;
    if (prefixLen < s.length() && s.charAt(prefixLen) == '(')
    {
      int close = s.indexOf(')', prefixLen);
      if (close < 0) return null;
      try
      {
        adjust = Integer.parseInt(s.substring(prefixLen + 1, close));
      }
      catch (NumberFormatException e)
      {
        return null;
      }
    }
    return new DateVal(kind, adjust);
  }

  @Override
  String getDefaultErrorMessage()
  {
    return INVALID_FORMAT;
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

  private static final class DateVal
  {
    static final int LITERAL = 0, DAY = 1, MONTH = 2, YEAR2 = 3, YEAR4 = 4;
    final int kind;
    final int adjust;

    DateVal(int kind, int adjust)
    {
      this.kind = kind;
      this.adjust = adjust;
    }

    int resolve(Calendar cal)
    {
      switch (kind)
      {
      case DAY:
      {
        int v = cal.get(Calendar.DAY_OF_MONTH) + adjust;
        return v > 31 ? 31 : v;
      }
      case MONTH:
      {
        int v = cal.get(Calendar.MONTH) + 1 + adjust;
        return v > 12 ? 12 : v;
      }
      case YEAR2:
        return cal.get(Calendar.YEAR) % 100 + adjust;
      case YEAR4:
        return cal.get(Calendar.YEAR) + adjust;
      default:
        return adjust;
      }
    }
  }

  private static final class DateRangeBlock extends FmtBlock
  {
    final DateVal min;
    final DateVal max;

    DateRangeBlock(String rawBlock)
    {
      String inner = rawBlock.substring(2, rawBlock.length() - 1);
      int sep = findRangeSep(inner);
      if (sep < 0)
      {
        min = null;
        max = null;
        return;
      }
      min = parseDateVal(inner.substring(0, sep));
      max = parseDateVal(inner.substring(sep + 1));
    }

    int match(String value, int pos, Calendar cal)
    {
      if (min == null || max == null || cal == null)
      {
        return ACCEPT_VALUE;
      }
      int minVal = min.resolve(cal);
      int maxVal = max.resolve(cal);
      return matchRange(value, pos, minVal, maxVal, numDigits(maxVal));
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
