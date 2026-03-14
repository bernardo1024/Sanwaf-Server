package com.sanwaf.core;

/**
 * Immutable pair of character offsets representing a region within a string.
 *
 * <p>Used to identify the start and end positions of error locations (e.g.
 * where a validation rule matched) so they can be reported in JSON output.
 */
final class Point {
  /** Inclusive start index of the region. */
  final int start;
  /** Exclusive end index of the region. */
  final int end;

  /**
   * Creates a point with the given start and end offsets.
   *
   * @param start inclusive start index
   * @param end   exclusive end index
   */
  Point(int start, int end) {
    this.start = start;
    this.end = end;
  }

  /**
   * Returns a human-readable representation of this point.
   *
   * @return a string in the form {@code "start: N, end: M"}
   */
  public String toString() {
    return "start: " + start + ", end: " + end;
  }
}
