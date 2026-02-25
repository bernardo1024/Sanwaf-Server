package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

final class ItemDependentFormat extends Item
{
  static final String INVALID_DEP_FORMAT = "Invalid Dependent Format: ";
  String depFormatString = null;
  String dependentElementName = null;
  Map<String, ItemFormat> formats = new HashMap<>();

  ItemDependentFormat(ItemData id)
  {
    super(id);
    initDependentFormat(id);
  }

  @Override
  List<Point> getErrorPoints(final Shield shield, final String value)
  {
    List<Point> points = new ArrayList<>();
    if (value.isEmpty() || !maskError.isEmpty())
    {
      return points;
    }
    points.add(new Point(0, value.length()));
    return points;
  }

  @Override
  boolean inError(final ServletRequest req, Shield shield, final String value, boolean doAllBlocks, boolean log)
  {
    if (mode == Modes.DISABLED)
    {
      return false;
    }
    String elementValue = null;
    if (dependentElementName != null)
    {
      elementValue = req.getParameter(dependentElementName);
    }
    if (elementValue == null)
    {
      return false;
    }
    ItemFormat format = getFormatForValue(elementValue);

    if (format != null && format.inError(req, shield, value, doAllBlocks, log))
    {
      return true;
    }
    return false;
  }

  private ItemFormat getFormatForValue(String value)
  {
    Iterator<Map.Entry<String, ItemFormat>> it = formats.entrySet().iterator();
    while (it.hasNext())
    {
      Map.Entry<String, ItemFormat> pair = it.next();
      if (value.equals(pair.getKey()))
      {
        return pair.getValue();
      }
    }
    return null;
  }

  @Override
  String modifyErrorMsg(ServletRequest req, String errorMsg)
  {
    if (req == null)
    {
      return "";
    }
    int i = errorMsg.indexOf(ItemFactory.XML_ERROR_MSG_PLACEHOLDER1);
    if (i >= 0)
    {
      String elementValue = req.getParameter(dependentElementName);
      ItemFormat format = getFormatForValue(elementValue);
      String formatString = " --- ";
      if (format != null)
      {
        formatString = format.formatString;
      }
      return errorMsg.substring(0, i) + Metadata.jsonEncode(formatString) + errorMsg.substring(i + ItemFactory.XML_ERROR_MSG_PLACEHOLDER1.length());
    }
    return errorMsg;
  }

  private void initDependentFormat(ItemData id)
  {
    int start = id.type.indexOf(ItemFactory.DEPENDENT_FORMAT);
    if (start >= 0)
    {
      depFormatString = id.type.substring(start + ItemFactory.DEPENDENT_FORMAT.length(), id.type.length() - 1);
      if (depFormatString.isEmpty())
      {
        return;
      }
      String[] elementFormatData = depFormatString.split(":");
      if (elementFormatData.length == 2)
      {
        dependentElementName = elementFormatData[0];
        String[] valueFormatPairs = elementFormatData[1].split(";");
        if (valueFormatPairs.length > 0)
        {
          parseFormats(id, valueFormatPairs);
        }
      }
    }
  }

  private void parseFormats(ItemData id, String[] valueFormatPairs)
  {
    for (String valueFormatPair : valueFormatPairs)
    {
      String[] kv = valueFormatPair.split("=");
      if (kv.length == 2)
      {
        id.type = "f{" + kv[1] + "}";
        ItemFormat item = new ItemFormat(id);
        formats.put(kv[0], item);
      }
    }
  }

  void setAdditionalFields()
  {
    Iterator<Map.Entry<String, ItemFormat>> it = formats.entrySet().iterator();
    while (it.hasNext())
    {
      Map.Entry<String, ItemFormat> pair = it.next();
      ItemFormat item = pair.getValue();
      item.required = required;
      item.maxValue = maxValue;
      item.minValue = minValue;
      item.related = related;
    }
  }

  @Override
  String getProperties()
  {
    StringBuilder sb = new StringBuilder();
    boolean isFirst = true;
    sb.append("\"formats\":{");
    String sep = "";
    for (Map.Entry<String, ItemFormat> entry : formats.entrySet())
    {
      if (!isFirst)
      {
        sep = ",";
      }
      else
      {
        isFirst = false;
      }
      sb.append(sep).append("\"key\":\"").append(entry.getKey()).append("\"");
      sb.append(",\"value\":\"").append(entry.getValue().formatString).append("\"");
    }
    sb.append("}");
    return sb.toString();
  }

  @Override
  Types getType()
  {
    return Types.DEPENDENT_FORMAT;
  }
}

