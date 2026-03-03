package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Collections;
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
    if (value == null || value.isEmpty() || !maskError.isEmpty())
    {
      return Collections.emptyList();
    }
    Rule r = this.rule;
    if (r == null)
    {
      r = shield.customRulePatterns.get(patternName);
      this.rule = r;
    }
    if (r == null || r.pattern == null)
    {
      return Collections.emptyList();
    }
    Matcher m = r.matcher(value);
    boolean found = m.find();
    if ((found && r.failOnMatch) || (!found && !r.failOnMatch))
    {
      return Collections.singletonList(new Point(0, value.length()));
    }
    return Collections.emptyList();
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (shouldSkipValidation(req, value))
    {
      return true;
    }
    Rule r = this.rule;
    if (r == null)
    {
      if (shield == null)
      {
        return false;
      }
      r = shield.customRulePatterns.get(patternName);
      if (r == null)
      {
        r = shield.customRulePatternsDetect.get(patternName);
      }
      this.rule = r;
    }
    if (r == null)
    {
      if (logger != null && logger.isWarnEnabled())
      {
        logger.warn("Pattern not found: " + patternName);
      }
      return false;
    }
    if (r.mode == Modes.DISABLED)
    {
      return false;
    }
    if (value.isEmpty())
    {
      return false;
    }
    if (r.pattern == null)
    {
      return false;
    }
    boolean match = r.matcher(value).find();
    if ((r.failOnMatch && match) || (!r.failOnMatch && !match))
    {
      handleMode(value, req, r.mode, log);
      return r.mode == Modes.BLOCK && mode == Modes.BLOCK;
    }
    return false;
  }

  @Override
  String getDefaultErrorMessage()
  {
    return FAILED_CUSTOM_PATTERN;
  }

  @Override
  String getProperties()
  {
    if (rule != null && rule.pattern != null)
    {
      return "\"regex\":\"" + JsonFormatter.jsonEncode(rule.pattern.toString()) + "\"";
    }
    else
    {
      return "\"regex\":\"" + JsonFormatter.jsonEncode(patternString) + "\"";
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

