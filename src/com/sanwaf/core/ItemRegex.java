package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ItemRegex extends Item
{
  static final String FAILED_CUSTOM_PATTERN = "Failed Custom Pattern: ";
  String patternName = null;
  String patternString = null;
  boolean isInline = false;
  Rule rule = null;

  ItemRegex(ItemData id)
  {
    super(id);
    setPattern(id);
  }

  @Override
  List<Point> getErrorPoints(final Shield shield, final String value)
  {
    List<Point> points = new ArrayList<>();
    if (value == null || value.isEmpty() || !maskError.isEmpty())
    {
      return points;
    }
    if (rule == null)
    {
      rule = shield.customRulePatterns.get(patternName);
    }
    Matcher m = rule.pattern.matcher(value);
    if ((m.find() && rule.failOnMatch) || (!m.find() && !rule.failOnMatch))
    {
      points.add(new Point(0, value.length()));
    }
    return points;
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    ModeError me = isModeError(req, value);
    if (me != null)
    {
      return true;
    }
    if (rule == null)
    {
      if (shield == null)
      {
        return false;
      }
      rule = shield.customRulePatterns.get(patternName);
      if (rule == null)
      {
        rule = shield.customRulePatternsDetect.get(patternName);
      }
    }
    if (rule.mode == Modes.DISABLED)
    {
      return false;
    }
    if (value.isEmpty())
    {
      return false;
    }
    boolean match = rule.pattern.matcher(value).find();
    if ((rule.failOnMatch && match) || (!rule.failOnMatch && !match))
    {
      handleMode(true, value, req, rule.mode, log);
      if (rule.mode == Modes.BLOCK && mode == Modes.BLOCK)
      {
        return true;
      }
    }
    return false;
  }

  private void setPattern(ItemData id)
  {
    String value = id.type;
    if (value.length() > 100)
    {
      patternString = value.substring(0, 100);
    }
    else
    {
      patternString = value;
    }

    if (value.startsWith(ItemFactory.INLINE_REGEX))
    {
      isInline = true;
      rule = new Rule();
      rule.pattern = Pattern.compile(value.substring(ItemFactory.INLINE_REGEX.length(), value.length() - 1), Pattern.CASE_INSENSITIVE);
      rule.mode = id.mode;
      rule.failOnMatch = false;
      patternName = "inline-regex: " + rule.pattern;
    }
    else
    {
      int start = value.indexOf(ItemFactory.REGEX);
      if (start >= 0)
      {
        patternName = value.substring(start + ItemFactory.REGEX.length(), value.length() - 1).toLowerCase();
      }
    }
  }

  @Override
  String getProperties()
  {
    if (rule != null && rule.pattern != null)
    {
      return "\"regex\":\"" + Metadata.jsonEncode(rule.pattern.toString()) + "\"";
    }
    else
    {
      return "\"regex\":\"" + Metadata.jsonEncode(patternString) + "\"";
    }
  }

  @Override
  Types getType()
  {
    if (isInline)
    {
      return Types.INLINE_REGEX;
    }
    return Types.REGEX;
  }
}

