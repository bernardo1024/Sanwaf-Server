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

  static final class Block
  {
    final String paramName;
    final String[] orValues;
    final boolean isAnd;

    Block(String paramName, String[] orValues, boolean isAnd)
    {
      this.paramName = paramName;
      this.orValues = orValues;
      this.isAnd = isAnd;
    }

    boolean evaluate(ServletRequest req, String value)
    {
      String parentValue = req.getParameter(paramName);
      if (orValues != null)
      {
        for (String or : orValues)
        {
          if (or.equals(parentValue))
          {
            return true;
          }
        }
        return false;
      }
      return parentValue != null && !parentValue.isEmpty() && value.isEmpty();
    }
  }

  static Block[] parseRelation(String related)
  {
    if (related == null || related.isEmpty() || related.endsWith(":="))
    {
      return null;
    }
    List<String> andBlocks = parseBlocks(related, 0, "AND", ")&&(", "(", ")");
    List<String> andOrBlocks = parseOrBlocksFromAndBlocks(andBlocks);
    List<Block> result = new ArrayList<>();
    boolean nextIsAnd = false;
    for (String entry : andOrBlocks)
    {
      if ("AND".equals(entry))
      {
        nextIsAnd = true;
        continue;
      }
      if ("OR".equals(entry))
      {
        nextIsAnd = false;
        continue;
      }
      String[] keyValue = COLON_PATTERN.split(entry, 2);
      String[] orValues = (keyValue.length > 1) ? DOUBLE_PIPE_PATTERN.split(keyValue[1]) : null;
      result.add(new Block(keyValue[0], orValues, nextIsAnd));
      nextIsAnd = false;
    }
    return result.toArray(new Block[0]);
  }

  static String validate(Block[] blocks, String related, String value, ServletRequest req, Metadata meta)
  {
    if (related == null || related.isEmpty())
    {
      return null;
    }
    if (related.endsWith(":="))
    {
      return isRelatedEqual(related, value, req, meta);
    }

    int andTrueCount = 0;
    int andTotalCount = 0;
    boolean orFoundTrue = false;
    for (Block block : blocks)
    {
      boolean condResult = block.evaluate(req, value);
      if (block.isAnd)
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
    }
    if (andTrueCount == andTotalCount && orFoundTrue && value.isEmpty())
    {
      return buildRequiredMessage(related, meta);
    }
    return null;
  }

  private static String buildRequiredMessage(String related, Metadata meta)
  {
    String raw = related;
    int paren = raw.indexOf('(');
    if (paren >= 0)
    {
      int end = raw.indexOf(')', paren);
      if (end > paren)
      {
        raw = raw.substring(paren + 1, end);
      }
    }
    int colon = raw.indexOf(':');
    String parentName = (colon > 0) ? raw.substring(0, colon).trim() : raw.trim();

    Item parentItem = meta.items.get(parentName);
    String parentDisplay = (parentItem != null) ? parentItem.display : parentName;
    if (related.contains("&&"))
    {
      return " - required based on related field conditions";
    }
    return " - required when \"" + parentDisplay + "\" has a value";
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
