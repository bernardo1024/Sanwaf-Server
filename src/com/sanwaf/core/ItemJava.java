package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
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

  private static Method resolveMethod(String sClazzAndMethod)
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
    catch (ClassNotFoundException | NullPointerException | NoSuchMethodException e)
    {
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

  static boolean runJavaMethod(Method method, String v, ServletRequest req)
  {
    try
    {
      Object o = method.invoke(null, v, req);
      return Boolean.TRUE.equals(o);
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

