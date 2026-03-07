package com.sanwaf.core;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

class Rule {
  final Modes mode;
  final Pattern pattern;
  final boolean failOnMatch;
  final String msg;
  private final ThreadLocal<Matcher> cachedMatcher;

  Rule(Modes mode, Pattern pattern, String match, String msg) {
    this.mode = mode;
    this.pattern = pattern;
    this.failOnMatch = !"pass".equalsIgnoreCase(match);
    this.msg = msg;
    this.cachedMatcher = pattern != null ? ThreadLocal.withInitial(() -> pattern.matcher("")) : null;
  }

  Matcher matcher(String value) {
    return cachedMatcher.get().reset(value);
  }
}
