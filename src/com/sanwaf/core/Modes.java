package com.sanwaf.core;

import java.util.HashMap;
import java.util.Map;

/**
 * Enumeration of operational modes that control how Sanwaf reacts to
 * validation failures.
 */
public enum Modes {
  /** Validation is disabled; no checks are performed. */
  DISABLED,
  /** Validation failures cause the request to be blocked. */
  BLOCK,
  /** Validation failures are logged but the request is allowed through. */
  DETECT,
  /** Like {@link #DETECT}, but every parameter is checked even after a failure is found. */
  DETECT_ALL;

  private static final Map<String, Modes> LOOKUP = new HashMap<>();
  static {
    for (Modes m : values()) {
      LOOKUP.put(m.name().toLowerCase(), m);
    }
  }

  /**
   * Resolves a mode string to a {@code Modes} constant.
   *
   * <p>The lookup is case-insensitive and tolerates hyphens and spaces
   * (e.g. {@code "detect-all"} maps to {@link #DETECT_ALL}).
   *
   * @param sMode the mode string to resolve
   * @param def   the default mode returned when {@code sMode} is unrecognised
   * @return the matching {@code Modes} constant, or {@code def} if not found
   */
  static Modes getMode(String sMode, Modes def) {
    String mode = sMode.toLowerCase().replace("-", "_").replace(" ", "");
    Modes m = LOOKUP.get(mode);
    return m != null ? m : def;
  }
}
