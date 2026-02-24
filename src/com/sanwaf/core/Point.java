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
    StringBuilder sb = new StringBuilder();
    sb.append("start: ").append(start);
    sb.append(", end: ").append(end);
    return sb.toString();
  }
}

