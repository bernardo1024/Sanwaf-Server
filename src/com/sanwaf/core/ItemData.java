package com.sanwaf.core;

class ItemData
{
  final String name;
  final String display;
  final Shield shield;
  String type;
  final int min;
  final int max;
  final String msg;
  final String uri;
  final Modes mode;

  ItemData(Shield shield, String name, Modes mode, String display, String type, String msg, String uri, int max, int min)
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
  }
}
