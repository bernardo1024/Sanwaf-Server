package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ItemRegex extends Item
{
  static final String FAILED_CUSTOM_PATTERN = "Failed Custom Pattern: ";
  final String patternName;
  final String patternString;
  final boolean isInline;
  volatile Rule rule = null;

  ItemRegex(ItemData id)
  {
    super(id);
    String value = id.type;
    this.patternString = value.length() > 100 ? value.substring(0, 100) : value;

    String pn = null;
    boolean il = false;
    if (value.startsWith(ItemFactory.INLINE_REGEX))
    {
      il = true;
      Pattern inlinePattern = Pattern.compile(value.substring(ItemFactory.INLINE_REGEX.length(), value.length() - 1), Pattern.CASE_INSENSITIVE);
      rule = new Rule(id.mode, inlinePattern, "pass", null);
      pn = "inline-regex: " + rule.pattern;
    }
    else
    {
      int start = value.indexOf(ItemFactory.REGEX);
      if (start >= 0)
      {
        pn = value.substring(start + ItemFactory.REGEX.length(), value.length() - 1);
      }
    }
    this.patternName = pn;
    this.isInline = il;
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
    Matcher m = rule.matcher(value);
    boolean found = m.find();
    if ((found && rule.failOnMatch) || (!found && !rule.failOnMatch))
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
    boolean match = rule.matcher(value).find();
    if ((rule.failOnMatch && match) || (!rule.failOnMatch && !match))
    {
      handleMode(true, value, req, rule.mode, log);
      return rule.mode == Modes.BLOCK && mode == Modes.BLOCK;
    }
    return false;
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

