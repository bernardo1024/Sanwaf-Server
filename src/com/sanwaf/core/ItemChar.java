package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Collections;
import java.util.List;

final class ItemChar extends Item
{
  static final String INVALID_CHAR = "Invalid Char: ";

  ItemChar(ItemData id)
  {
    super(id);
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (hasPreValidationError(req, value))
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
    if (value == null || !maskError.isEmpty())
    {
      return Collections.emptyList();
    }
    return Collections.singletonList(new Point(0, value.length()));
  }

  @Override
  String getDefaultErrorMessage()
  {
    return INVALID_CHAR;
  }

  @Override
  Types getType()
  {
    return Types.CHAR;
  }
}

