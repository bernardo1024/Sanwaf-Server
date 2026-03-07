package com.sanwaf.core;

import java.util.HashMap;
import java.util.Map;

public enum Modes {
  DISABLED, BLOCK, DETECT, DETECT_ALL;

  private static final Map<String, Modes> LOOKUP = new HashMap<>();
  static {
    for (Modes m : values()) {
      LOOKUP.put(m.name().toLowerCase(), m);
    }
  }

  static Modes getMode(String sMode, Modes def) {
    String mode = sMode.toLowerCase().replace("-", "_").replace(" ", "");
    Modes m = LOOKUP.get(mode);
    return m != null ? m : def;
  }
}
