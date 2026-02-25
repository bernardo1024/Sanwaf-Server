package com.sanwaf.core;

final class Point
{
  final int start;
  final int end;

  Point(int start, int end)
  {
    this.start = start;
    this.end = end;
  }

  public String toString()
  {
    return "start: " + start + ", end: " + end;
  }
}

