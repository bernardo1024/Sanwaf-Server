package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;

final class ItemString extends Item
{
  static final ItemString DEFAULT_INSTANCE = new ItemString();
  static final String FAILED_PATTERN = "Failed Pattern: ";

  ItemString()
  {
  }

  ItemString(ItemData id)
  {
    super(id);
  }

  @Override
  List<Point> getErrorPoints(final Shield shield, final String value)
  {
    if (shield == null || !maskError.isEmpty())
    {
      return Collections.emptyList();
    }
    List<Point> points = null;
    for (Rule r : shield.rulePatterns.values())
    {
      if (r.pattern == null)
      {
        continue;
      }
      Matcher m = r.matcher(value);
      while (m.find())
      {
        if (points == null)
        {
          points = new ArrayList<>();
        }
        points.add(new Point(m.start(), m.end()));
      }
    }
    return points != null ? points : Collections.emptyList();
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (shouldSkipValidation(req, value))
    {
      return true;
    }
    boolean inError = false;
    if (shield != null)
    {
      if (value.length() < shield.regexMinLen)
      {
        return false;
      }
      //first process the detects & detect all - ignore the return value for detect
      if (!shield.rulePatternsDetect.isEmpty())
      {
        isInErrorForPatterns(req, shield.rulePatternsDetect, value, doAllBlocks);
      }
      //then do the blocks
      inError = isInErrorForPatterns(req, shield.rulePatterns, value, doAllBlocks);
    }
    if (mode == Modes.DETECT || mode == Modes.DETECT_ALL)
    {
      return false;
    }
    return inError;
  }

  private boolean isInErrorForPatterns(final ServletRequest req, Map<String, Rule> patterns, final String value, boolean doAllBlocks)
  {
    boolean inError = false;
    for (Rule r : patterns.values())
    {
      Modes ruleMode = r.mode;
      if (ruleMode != Modes.DISABLED)
      {
        if (r.pattern == null)
        {
          continue;
        }
        boolean match = r.matcher(value).find();
        if ((r.failOnMatch && match) || (!r.failOnMatch && !match))
        {
          if (r.mode == Modes.BLOCK)
          {
            inError = true;
            handleMode(value, req, ruleMode, true, doAllBlocks, null);
          }
          else
          {
            handleMode(value, req, ruleMode, true);
          }
          if (doAllBlocks || (mode != Modes.DETECT_ALL && ruleMode != Modes.DETECT_ALL))
          {
            break;
          }
        }
      }
    }
    return inError;
  }

  @Override
  String getDefaultErrorMessage()
  {
    return FAILED_PATTERN;
  }

  @Override
  Types getType()
  {
    return Types.STRING;
  }
}

