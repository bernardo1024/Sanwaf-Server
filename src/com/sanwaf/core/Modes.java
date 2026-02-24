package com.sanwaf.core;

public enum Modes
{
  DISABLED, BLOCK, DETECT, DETECT_ALL;

  static Modes getMode(String sMode, Modes def)
  {
    switch (sMode.toLowerCase())
    {
    case "disabled":
      return DISABLED;
    case "block":
      return BLOCK;
    case "detect":
      return DETECT;
    case "detect_all":
      return DETECT_ALL;
    case "detect-all":
      return DETECT_ALL;
    case "detectall":
      return DETECT_ALL;
    default:
      return def;
    }
  }
}

