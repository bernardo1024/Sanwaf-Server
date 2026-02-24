package com.sanwaf.core;

class ItemData
{
  String name;
  String display;
  Shield shield;
  String type;
  int min;
  int max;
  String msg;
  String uri;
  Modes mode;

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
