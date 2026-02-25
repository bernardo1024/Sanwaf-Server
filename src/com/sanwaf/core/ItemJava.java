package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

final class ItemJava extends Item
{
  static final String INVALID_JAVA = "Invalid Java: ";
  Method javaMethod = null;
  String sClazzAndMethod = null;

  ItemJava(ItemData id)
  {
    super(id);
    setJavaMethod(id.type);
  }

  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    ModeError me = isModeError(req, value);
    if (me != null)
    {
      return true;
    }
    if (value.isEmpty())
    {
      return false;
    }
    return runJavaMethod(javaMethod, value, req);
  }

  @Override
  List<Point> getErrorPoints(Shield shield, String value)
  {
    List<Point> points = new ArrayList<>();
    if (!maskError.isEmpty())
    {
      return points;
    }
    points.add(new Point(0, value.length()));
    return points;
  }

  private void setJavaMethod(String type)
  {
    sClazzAndMethod = type.substring(type.indexOf(ItemFactory.JAVA) + ItemFactory.JAVA.length(), type.length() - 1);
    if (sClazzAndMethod.isEmpty())
    {
      return;
    }

    Class<?> clazz = null;
    try
    {
      clazz = Class.forName(parseClazz(sClazzAndMethod));
      javaMethod = clazz.getMethod(parseMethod(sClazzAndMethod), String.class, ServletRequest.class);
    }
    catch (ClassNotFoundException | NullPointerException | NoSuchMethodException e)
    {
      javaMethod = null;
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

  static boolean runJavaMethod(Method method, String v, ServletRequest req)
  {
    try
    {
      Object o = method.invoke(null, v, req);
      return Boolean.parseBoolean(String.valueOf(o));
    }
    catch (NullPointerException | IllegalAccessException | InvocationTargetException e)
    {
      return true;
    }
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

