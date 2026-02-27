package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;

final class ItemJava extends Item
{
  static final String INVALID_JAVA = "Invalid Java: ";
  final Method javaMethod;
  final String sClazzAndMethod;

  ItemJava(ItemData id)
  {
    super(id);
    String type = id.type;
    this.sClazzAndMethod = type.substring(type.indexOf(ItemFactory.JAVA) + ItemFactory.JAVA.length(), type.length() - 1);
    this.javaMethod = resolveMethod(sClazzAndMethod);
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (shouldSkipValidation(req, value))
    {
      return true;
    }
    if (value.isEmpty())
    {
      return false;
    }
    if (javaMethod == null)
    {
      return true;
    }
    return runJavaMethod(javaMethod, value, req);
  }

  @Override
  List<Point> getErrorPoints(Shield shield, String value)
  {
    if (!maskError.isEmpty())
    {
      return Collections.emptyList();
    }
    return Collections.singletonList(new Point(0, value.length()));
  }

  private Method resolveMethod(String sClazzAndMethod)
  {
    if (sClazzAndMethod.isEmpty())
    {
      return null;
    }
    try
    {
      Class<?> clazz = Class.forName(parseClazz(sClazzAndMethod));
      return clazz.getMethod(parseMethod(sClazzAndMethod), String.class, ServletRequest.class);
    }
    catch (ClassNotFoundException | NoSuchMethodException e)
    {
      if (logger != null && logger.isErrorEnabled())
      {
        logger.error("ItemJava: failed to resolve " + sClazzAndMethod + " - " + e);
      }
      return null;
    }
  }

  static String parseClazz(String s)
  {
    int last = s.lastIndexOf('.');
    if (last > 0)
    {
      return s.substring(0, last);
    }
    return s;
  }

  static String parseMethod(String s)
  {
    int start = s.lastIndexOf('.');
    if (start > 0)
    {
      int end = s.lastIndexOf('(');
      if (end > 0)
      {
        return s.substring(start + 1, end);
      }
    }
    return s;
  }

  boolean runJavaMethod(Method method, String v, ServletRequest req)
  {
    try
    {
      Object o = method.invoke(null, v, req);
      return Boolean.TRUE.equals(o);
    }
    catch (IllegalAccessException | InvocationTargetException e)
    {
      if (logger != null && logger.isErrorEnabled())
      {
        logger.error("ItemJava: error invoking " + sClazzAndMethod + " - " + e);
      }
      return true;
    }
  }

  @Override
  String getDefaultErrorMessage()
  {
    return INVALID_JAVA;
  }

  @Override
  String getProperties()
  {
    return "\"typespecific\":\"" + Metadata.jsonEncode(sClazzAndMethod) + "\"";
  }

  @Override
  Types getType()
  {
    return Types.JAVA;
  }
}

