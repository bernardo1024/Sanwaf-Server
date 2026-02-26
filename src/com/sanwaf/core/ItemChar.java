package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class ItemChar extends Item
{
  static final String INVALID_CHAR = "Invalid Constant: ";

  ItemChar(ItemData id)
  {
    super(id);
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (shouldSkipValidation(req, value))
    {
      return true;
    }
    if (value == null)
    {
      return false;
    }
    return value.length() > 1;
  }

  @Override
  List<Point> getErrorPoints(Shield shield, String value)
  {
    if (!maskError.isEmpty())
    {
      return Collections.emptyList();
    }
    List<Point> points = new ArrayList<>();
    points.add(new Point(0, value.length()));
    return points;
  }

  @Override
  Types getType()
  {
    return Types.CHAR;
  }
}

