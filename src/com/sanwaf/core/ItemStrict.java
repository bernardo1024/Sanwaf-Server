package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.Collections;
import java.util.List;

public class ItemStrict extends Item
{

  ItemStrict(String s)
  {
    msg = s;
  }

  @Override
  boolean inError(ServletRequest req, Shield shield, String value, boolean doAllBlocks, boolean log)
  {
    return false;
  }

  @Override
  List<Point> getErrorPoints(Shield shield, String value)
  {
    return Collections.emptyList();
  }

  @Override
  Types getType()
  {
    return Types.STRICT;
  }

}
