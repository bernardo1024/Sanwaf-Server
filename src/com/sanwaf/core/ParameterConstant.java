package com.sanwaf.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.ServletRequest;

final class ParameterConstant extends Parameter {
  List<String> constantValues = null;

  ParameterConstant(String name, String type, int max, int min, String errorMsg, String path) {
    super(name, max, min, errorMsg, path);
    this.type = Metadata.TYPE_CONSTANT;
    addConstantToType(type);
  }

  @Override
  public List<Point> getErrorPoints(final Shield shield, final String value) {
    List<Point> points = new ArrayList<>();
    points.add(new Point(0, value.length()));
    return points;
  }

  @Override
  public boolean inError(final ServletRequest req, final Shield shield, final String value) {
    if (isSizeError(value)) {
      return true;
    }
    return !constantValues.contains(value);
  }

  private void addConstantToType(String value) {
    int start = value.indexOf(Metadata.TYPE_CONSTANT);
    if (start >= 0) {
      String s = value.substring(start + Metadata.TYPE_CONSTANT.length(), value.length() - 1);
      constantValues = new ArrayList<>(Arrays.asList(s.split(",")));
    }
  }

  @Override
  public String modifyErrorMsg(String errorMsg) {
    int i = errorMsg.indexOf(Error.XML_ERROR_MSG_PLACEHOLDER);
    if (i >= 0) {
      return errorMsg.substring(0, i) + Metadata.jsonEncode(constantValues.toString()) + errorMsg.substring(i + Error.XML_ERROR_MSG_PLACEHOLDER.length(), errorMsg.length());
    }
    return errorMsg;
  }
}
