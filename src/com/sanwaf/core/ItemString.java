package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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
    Rule[] rules = shield.rulePatternsArray;
    for (Rule r : rules)
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
    if (hasPreValidationError(req, value))
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
      if (shield.canSkipByCharScan && Shield.containsNoXssRelevantChar(value))
      {
        return false;
      }
      //first process the detects & detect all - ignore the return value for detect
      //skip when item is BLOCK and caller wants fast-fail (doAllBlocks=false)
      if (shield.rulePatternsDetectArray.length > 0
          && (doAllBlocks || mode == Modes.DETECT || mode == Modes.DETECT_ALL))
      {
        isInErrorForPatterns(req, shield.rulePatternsDetectArray, value, doAllBlocks);
      }
      //then do the blocks
      inError = isInErrorForPatterns(req, shield.rulePatternsArray, value, doAllBlocks);
    }
    if (mode == Modes.DETECT || mode == Modes.DETECT_ALL)
    {
      return false;
    }
    return inError;
  }

  private boolean isInErrorForPatterns(final ServletRequest req, Rule[] rules, final String value, boolean doAllBlocks)
  {
    boolean inError = false;
    for (Rule r : rules)
    {
      Modes ruleMode = r.mode;
      if (ruleMode != Modes.DISABLED)
      {
        if (r.pattern == null)
        {
          continue;
        }
        Matcher m = r.matcher(value);
        boolean match = m.find();
        if ((r.failOnMatch && match) || (!r.failOnMatch && !match))
        {
          List<Point> points = match ? collectMatchPoints(m) : null;
          if (r.mode == Modes.BLOCK)
          {
            inError = true;
            handleMode(value, req, ruleMode, true, doAllBlocks, null, points);
          }
          else
          {
            handleMode(value, req, ruleMode, true, points);
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

  private static List<Point> collectMatchPoints(Matcher m)
  {
    List<Point> points = new ArrayList<>();
    do
    {
      points.add(new Point(m.start(), m.end()));
    }
    while (m.find());
    return points;
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

