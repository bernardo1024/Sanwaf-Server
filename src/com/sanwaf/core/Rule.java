package com.sanwaf.core;

import java.util.regex.Pattern;

class Rule
{
  final Modes mode;
  final Pattern pattern;
  final boolean failOnMatch;
  final String msg;
  Rule(Modes mode, Pattern pattern, String match, String msg)
  {
    this.mode = mode;
    this.pattern = pattern;
    this.failOnMatch = !"pass".equalsIgnoreCase(match);
    this.msg = msg;
  }
}
