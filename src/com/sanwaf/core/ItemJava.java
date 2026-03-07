package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;

/**
 * Validates input values by invoking a user-supplied static Java method
 * via reflection.
 *
 * <p>The type string specifies a fully qualified class name and method name
 * in the form {@code j{com.example.MyClass.validate()}}. The referenced
 * method must be a public static method with the signature:
 * <pre>
 *   public static Boolean methodName(String value, ServletRequest req)
 * </pre>
 *
 * <p>The method must return {@code Boolean.TRUE} to indicate the value is
 * in error, or {@code Boolean.FALSE} / {@code null} to indicate the value
 * is valid.
 */
final class ItemJava extends Item {
  /** Default error message prefix for Java validation failures. */
  static final String INVALID_JAVA = "Invalid Java: ";
  /** The resolved reflective method handle, or {@code null} if resolution failed. */
  final Method javaMethod;
  /** The raw "class.method()" string from configuration. */
  final String sClazzAndMethod;

  /**
   * Constructs a Java item by extracting the class/method specification
   * from the type string and resolving it to a {@link Method} via reflection.
   *
   * @param id item configuration data containing the Java type string
   */
  ItemJava(ItemData id) {
    super(id);
    String type = id.type;
    this.sClazzAndMethod = type.substring(type.indexOf(ItemFactory.JAVA) + ItemFactory.JAVA.length(), type.length() - 1);
    this.javaMethod = resolveMethod(sClazzAndMethod);
  }

  /**
   * Validates the input value by invoking the configured Java method.
   *
   * <p>Returns {@code true} (error) if:
   * <ul>
   *   <li>Pre-validation checks fail (mode/required)</li>
   *   <li>The method could not be resolved at construction time</li>
   *   <li>The invoked method returns {@code Boolean.TRUE}</li>
   *   <li>The method throws an exception</li>
   * </ul>
   *
   * <p>Empty values are accepted without invoking the method.
   *
   * @param req         the servlet request (passed to the validation method)
   * @param shield      the active shield (unused)
   * @param value       the input value to validate
   * @param doAllBlocks whether to process all detection blocks
   * @param log         whether to log violations
   * @return {@code true} if the value is considered invalid
   */
  @Override
  boolean inError(final ServletRequest req, final Shield shield, final String value, boolean doAllBlocks, boolean log) {
    if (hasPreValidationError(req, value)) {
      return true;
    }
    if (value.isEmpty()) {
      return false;
    }
    if (javaMethod == null) {
      return true;
    }
    return runJavaMethod(javaMethod, value, req);
  }

  /**
   * Returns error highlight points spanning the entire value.
   *
   * @param shield the active shield (unused)
   * @param value  the input value being validated
   * @return a single-element list covering the full value, or empty
   *         if error masking is active
   */
  @Override
  List<Point> getErrorPoints(Shield shield, String value) {
    if (!maskError.isEmpty()) {
      return Collections.emptyList();
    }
    return Collections.singletonList(new Point(0, value.length()));
  }

  /**
   * Resolves the class and method specified by the configuration string
   * into a reflective {@link Method} handle.
   *
   * @param sClazzAndMethod fully qualified class and method name
   *                        (e.g., {@code "com.example.Validator.check()"})
   * @return the resolved method, or {@code null} if the class or method
   *         cannot be found
   */
  private Method resolveMethod(String sClazzAndMethod) {
    if (sClazzAndMethod.isEmpty()) {
      return null;
    }
    try {
      Class<?> clazz = Class.forName(parseClazz(sClazzAndMethod));
      return clazz.getMethod(parseMethod(sClazzAndMethod), String.class, ServletRequest.class);
    } catch (ClassNotFoundException | NoSuchMethodException e) {
      if (logger != null && logger.isErrorEnabled()) {
        logger.error("ItemJava: failed to resolve " + sClazzAndMethod + " - " + e);
      }
      return null;
    }
  }

  /**
   * Extracts the fully qualified class name from a "class.method()" string
   * by taking everything before the last dot.
   *
   * @param s the class-and-method string
   * @return the class name portion, or the entire string if no dot is found
   */
  static String parseClazz(String s) {
    int last = s.lastIndexOf('.');
    if (last > 0) {
      return s.substring(0, last);
    }
    return s;
  }

  /**
   * Extracts the method name from a "class.method()" string by taking the
   * text between the last dot and the opening parenthesis.
   *
   * @param s the class-and-method string
   * @return the method name, or the entire string if parsing fails
   */
  static String parseMethod(String s) {
    int start = s.lastIndexOf('.');
    if (start > 0) {
      int end = s.lastIndexOf('(');
      if (end > 0) {
        return s.substring(start + 1, end);
      }
    }
    return s;
  }

  /**
   * Invokes the validation method reflectively with the given value and request.
   *
   * @param method the static method to invoke
   * @param v      the input value to pass as the first argument
   * @param req    the servlet request to pass as the second argument
   * @return {@code true} if the method returns {@code Boolean.TRUE} or
   *         if invocation fails (treated as an error)
   */
  boolean runJavaMethod(Method method, String v, ServletRequest req) {
    try {
      Object o = method.invoke(null, v, req);
      return Boolean.TRUE.equals(o);
    } catch (IllegalAccessException | InvocationTargetException e) {
      if (logger != null && logger.isErrorEnabled()) {
        logger.error("ItemJava: error invoking " + sClazzAndMethod + " - " + e);
      }
      return true;
    }
  }

  /** {@inheritDoc} */
  @Override
  String getDefaultErrorMessage() {
    return INVALID_JAVA;
  }

  /**
   * Returns a JSON fragment with the class/method specification.
   *
   * @return JSON key-value pair with the encoded class-and-method string
   */
  @Override
  String getProperties() {
    return "\"typespecific\":\"" + JsonFormatter.jsonEncode(sClazzAndMethod) + "\"";
  }

  /** {@inheritDoc} */
  @Override
  Types getType() {
    return Types.JAVA;
  }
}
