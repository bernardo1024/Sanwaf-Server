package com.sanwaf.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;

import jakarta.servlet.ServletRequest;

final class ItemString extends Item {
  static final String FAILED_PATTERN = "Failed Pattern: ";
  static final String MATCHED_PATTERN = "Matched Pattern: ";

  ItemString() {
  }

  ItemString(ItemData id) {
    super(id);
  }

  @Override
  List<Point> getErrorPoints(final Shield shield, final String value) {
    List<Point> points = new ArrayList<>();
    if (shield == null || maskError.length() > 0) {
      return points;
    }
    for (Map.Entry<String, Rule> r : shield.rulePatterns.entrySet()) {
      Matcher m = r.getValue().pattern.matcher(value);
      while (m.find()) {
        int start = m.start();
        int end = m.end();
        points.add(new Point(start, end));
      }
    }
    return points;
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log) {
    ModeError me = isModeError(req, value);
    if (me != null) {
      return true;
    }
    boolean inError = false;
    if (shield != null) {
      //first process the detects & detect all - ignore the return value for detect
      isInErrorForPatterns(req, shield.rulePatternsDetect, value, doAllBlocks);
      //then do the blocks
      inError = isInErrorForPatterns(req, shield.rulePatterns, value, doAllBlocks);
    }
    if (mode == Modes.DETECT || mode == Modes.DETECT_ALL) {
      return false;
    }
    return inError;
  }

  private boolean isInErrorForPatterns(final ServletRequest req, Map<String, Rule> patterns, final String value, boolean doAllBlocks) {
    boolean inError = false;
    for (Map.Entry<String, Rule> rule : patterns.entrySet()) {
      Modes ruleMode = rule.getValue().mode;
      if (ruleMode != Modes.DISABLED) {
        boolean match = rule.getValue().pattern.matcher(value).find();
        if ((rule.getValue().failOnMatch && match) || (!rule.getValue().failOnMatch && !match)) {
          if (rule.getValue().mode == Modes.BLOCK) {
            inError = true;
            handleMode(true, value, req, ruleMode, true, doAllBlocks);
          } else {
            handleMode(true, value, req, ruleMode, true);
          }
          if (doAllBlocks || (mode != Modes.DETECT_ALL && ruleMode != Modes.DETECT_ALL)) {
            break;
          }
        }
      }
    }
    return inError;
  }

  @Override
  Types getType() {
    return Types.STRING;
  }
}

