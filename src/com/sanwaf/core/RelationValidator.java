package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

final class RelationValidator
{
  private static final Pattern COLON_PATTERN = Pattern.compile(":");
  private static final Pattern DOUBLE_PIPE_PATTERN = Pattern.compile("\\|\\|");

  private RelationValidator()
  {
  }

  static String validate(String related, String value, ServletRequest req, Metadata meta)
  {
    if (related == null || related.isEmpty())
    {
      return null;
    }
    if (related.endsWith(":="))
    {
      return isRelatedEqual(related, value, req, meta);
    }

    List<String> andBlocks = parseBlocks(related, 0, "AND", ")&&(", "(", ")");
    List<String> andOrBlocks = parseOrBlocksFromAndBlocks(andBlocks);
    int andTrueCount = 0;
    int andTotalCount = 0;
    boolean orFoundTrue = false;
    boolean nextIsAnd = false;
    boolean skipIteration = false;
    for (int i = 0; i < andOrBlocks.size(); i++)
    {
      if (skipIteration)
      {
        skipIteration = false;
        continue;
      }
      boolean condResult = isRelatedBlockMakingChildRequired(andOrBlocks.get(i), value, req);
      if (nextIsAnd)
      {
        andTotalCount++;
        if (condResult)
        {
          andTrueCount++;
        }
      }
      else if (condResult)
      {
        orFoundTrue = true;
      }
      nextIsAnd = false;
      if (andOrBlocks.size() > i + 1)
      {
        if (andOrBlocks.get(i + 1).equals("AND"))
        {
          nextIsAnd = true;
        }
        skipIteration = true;
      }
    }
    String err = null;
    if (andTrueCount == andTotalCount && orFoundTrue && value.isEmpty())
    {
      // TODO: add better message
      err = " - Invalid relationship detected";
    }
    return err;
  }

  private static List<String> parseOrBlocksFromAndBlocks(List<String> andBlocks)
  {
    List<String> andOrBlocks = new ArrayList<>();
    List<String> blocks;
    for (String andBlock : andBlocks)
    {
      blocks = parseBlocks(andBlock, 0, "OR", ")||(", "(", ")");
      for (int j = 0; j < blocks.size(); j++)
      {
        if (blocks.get(j).equals("||"))
        {
          blocks.set(j, "OR");
        }
        else if (blocks.get(j).endsWith(")||"))
        {
          String block = blocks.get(j);
          blocks.set(j, block.substring(1, block.length() - 3));
          blocks.add(j + 1, "OR");
        }
      }
      andOrBlocks.addAll(blocks);
    }
    return andOrBlocks;
  }

  private static boolean isRelatedBlockMakingChildRequired(String block, String value, ServletRequest req)
  {
    String[] tagKeyValuePair = COLON_PATTERN.split(block);
    String parentValue = req.getParameter(tagKeyValuePair[0]);

    int parentLen = 0;
    if (parentValue != null)
    {
      parentLen = parentValue.length();
    }

    if (tagKeyValuePair.length > 1)
    {
      String[] ors = DOUBLE_PIPE_PATTERN.split(tagKeyValuePair[1]);
      for (String or : ors)
      {
        if (or.equals(parentValue))
        {
          return true;
        }
      }
      return false;
    }

    return parentLen > 0 && value.isEmpty();
  }

  private static String isRelatedEqual(String related, String value, ServletRequest req, Metadata meta)
  {
    String[] tagKeyValuePair = COLON_PATTERN.split(related);
    String parentValue = req.getParameter(tagKeyValuePair[0]);
    if (value.equals(parentValue))
    {
      return null;
    }
    Item parentItem = meta.items.get(tagKeyValuePair[0]);
    return parentItem == null ? null : " - does not match \"" + parentItem.display + "\"";
  }

  private static List<String> parseBlocks(String s, int start, String andOr, String match, String reverseMatch,
      String forwardMatch)
  {
    List<String> blocks = new ArrayList<>();
    int lastPos = start;
    while (true)
    {
      int pos = s.indexOf(match, lastPos);
      if (pos > 0)
      {
        start = s.lastIndexOf(reverseMatch, pos);
        if (start != lastPos)
        {
          blocks.add(s.substring(lastPos, start));
        }
        blocks.add(s.substring(start + reverseMatch.length(), pos));
        blocks.add(andOr);
        int end = s.indexOf(forwardMatch, pos + match.length());
        blocks.add(s.substring(pos + match.length(), end));
        lastPos = end + forwardMatch.length();
      }
      else
      {
        if (lastPos + 1 < s.length())
        {
          blocks.add(s.substring(lastPos));
        }
        break;
      }
    }
    return blocks;
  }
}
