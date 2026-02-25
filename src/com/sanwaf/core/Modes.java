package com.sanwaf.core;

public enum Modes
{
  DISABLED, BLOCK, DETECT, DETECT_ALL;

  static Modes getMode(String sMode, Modes def)
  {
    String mode = sMode.toLowerCase().replace("-", "_").replace(" ", "");
    for (Modes m : values())
    {
      if (m.name().equalsIgnoreCase(mode))
      {
        return m;
      }
    }
    return def;
  }
}

