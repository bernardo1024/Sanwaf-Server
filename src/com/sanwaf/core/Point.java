package com.sanwaf.core;

final class Point
{
  int start;
  int end;

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

