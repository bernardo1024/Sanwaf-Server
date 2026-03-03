package com.sanwaf.core;

import com.sanwaf.log.Logger;

class ItemData
{
  final String name;
  final String display;
  final Shield shield;
  final String type;
  final int min;
  final int max;
  final String msg;
  final String uri;
  final Modes mode;
  final Logger logger;
  final boolean required;
  final double maxValue;
  final double minValue;
  final String maskError;
  final String related;
  final RelationValidator.Block[] relatedBlocks;

  ItemData(Shield shield, String name, Modes mode, String display, String type, String msg, String uri, int max, int min)
  {
    this(shield, name, mode, display, type, msg, uri, max, min,
        shield != null ? shield.logger : null, false, Integer.MAX_VALUE, Integer.MIN_VALUE, "", null, null);
  }

  ItemData(Shield shield, String name, Modes mode, String display, String type, String msg, String uri, int max, int min,
      Logger logger, boolean required, double maxValue, double minValue, String maskError, String related, RelationValidator.Block[] relatedBlocks)
  {
    this.name = name;
    this.display = display;
    this.shield = shield;
    this.type = type;
    this.min = min;
    this.max = max;
    this.msg = msg;
    this.uri = uri;
    this.mode = mode;
    this.logger = logger;
    this.required = required;
    this.maxValue = maxValue;
    this.minValue = minValue;
    this.maskError = maskError;
    this.related = related;
    this.relatedBlocks = relatedBlocks;
  }
}
