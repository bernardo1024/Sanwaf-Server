package com.sanwaf.core;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.springframework.mock.web.MockHttpServletRequest;

import com.sanwaf.core.Shield;
import com.sanwaf.core.Sanwaf;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EndpointsTest {
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeClass
  public static void setUpClass() {
    try {
      sanwaf = new Sanwaf();
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    } catch (IOException ioe) {
      assertTrue(false);
    }
  }

  @Test
  public void testEndpointChar() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("char", "a");
    Boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("char", "aa");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);
  }

  @Test
  public void testEndpointRegex() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("endpointRegex", "a");
    Boolean isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("endpointRegex", "foo@bar.com");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);
  }

  @Test
  public void testEndpointMaxMinValue() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {

    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("max-min-value", "10");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("max-min-value", "100");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("max-min-value", "20");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("max-min-value", "9");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("max-min-value", "101");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("max-min-value", "aa");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("max-min-value", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("max-min-value-required", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);
  }

  @Test
  public void testEndpointRequired() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("required", "a");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("required", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);
  }

  @Test
  public void testEndpointOpen() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("open", "(123) 456-7890 abz ABZ");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);
  }

  @Test
  public void testEndpointFormat() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "(123) 456-7890 abz ABZ");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "(123) 456-7890 zba ZBA");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "(123) 456-7890 ABC ABC");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "(aaa) aaa-aaaa ABC ABC");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "(   )    -     ABC ABC");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "(123) 456-7890 ||| ABC");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "(123) 456-7890 abz    ");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "(123) 456-7890 abz zba");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", " 123 456 7890 abc abc");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", " 123 456 7890 123 ABC");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", " 123 456 7890 abc 123");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", " 123  456 7890 abc ABC");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", " abc 456 7890 abc ABC");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "(abc) 456-7890 abc ABC");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "(123) 456-789 abc ABC");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "1234567890");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("format", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("formatRequired", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);
  }

  @Test
  public void testEndpointRelatedSimple() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    // related-simple-child<related>related-simple-parent</related>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-simple-child", "aaa");
    request.addParameter("related-simple-parent", "aaa");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-simple-child", "aaa");
    request.addParameter("related-simple-parent", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-simple-child", "");
    request.addParameter("related-simple-parent", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);
  }

  @Test
  public void testEndpointRelatedInvalidConfig() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    // related-invalid-child<related>related-invalid</related>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-invalid-child", "aaa");
    request.addParameter("related-invalid-parent", "aaa");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-invalid-child", "aaa");
    request.addParameter("related-invalid-parent", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-invalid-child", "");
    request.addParameter("related-invalid-parent", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/invalid-uri/test.jsp");
    request.addParameter("related-invalid-child", "");
    request.addParameter("related-invalid-parent", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    // related-invalidX-child<related>(related-invalidX1-parent)(related-invalidX2-parent)</related>
    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/invalid-uri/test.jsp");
    request.addParameter("related-invalidX-child", "");
    request.addParameter("related-invalidX1-parent", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);
  }

  @Test
  public void testEndpointRelatedEqualsNoParent() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-equals-req-parent", "aaa");
    request.addParameter("related-equals-req-child", "");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);
  }
  
  @Test
  public void testEndpointRelatedEquals() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    // related-equals-child<related>related-equals-parent:=</related>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-equals-child", "aaa");
    request.addParameter("related-equals-parent", "aaa");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-equals-req-parent", "aaa");
    request.addParameter("related-equals-req-child", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-equals-child", "1111");
    request.addParameter("related-equals-parent", "2222");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-equals-child", "1111");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-equals-child", "11111");
    request.addParameter("related-equals-parent", "2222");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-equals-child", "1111");
    request.addParameter("related-equals-parent", "22222");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-equals-child", "aaa");
    request.addParameter("related-equals-parent", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-equals-child", "");
    request.addParameter("related-equals-parent", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-equals-req-child", "aaa");
    request.addParameter("related-equals-req-parent", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-equals-req-child", "");
    request.addParameter("related-equals-req-parent", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);
  }

  @Test
  public void testEndpointRelatedNoParentDefined() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    // related-simple-or-no-parent-parent:Yes<
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-simple-or-no-parent-child", "");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-simple-or-no-parent-child", "");
    request.addParameter("related-simple-or-no-parent-parent", "Yes");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-simple-or-no-parent-child", "abcdefg");
    request.addParameter("related-simple-or-no-parent-parent", "Yes");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);
  }

  @Test
  public void testEndpointRelatedSimpleOr() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    // related-simple-or-child<related>related-simple-or-parent:aaa||bbb</related>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-simple-or-child", "aaa");
    request.addParameter("related-simple-or-parent", "aaa");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-simple-or-child", "aaa");
    request.addParameter("related-simple-or-parent", "bbb");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-simple-or-child", "");
    request.addParameter("related-simple-or-parent", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-simple-or-child", "");
    request.addParameter("related-simple-or-parent", "bbb");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-simple-or-child", "aaa");
    request.addParameter("related-simple-or-parent", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);
  }

  @Test
  public void testEndpointRelatedOr() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    // related-or-child<related>(related-or-parent1:aaa||bbb)||(related-or-parent2:ccc||ddd)</related>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-or-child", "aaa");
    request.addParameter("related-or-parent1", "aaa");
    request.addParameter("related-or-parent2", "ccc");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-or-child", "aaa");
    request.addParameter("related-or-parent1", "bbb");
    request.addParameter("related-or-parent2", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-or-child", "aaa");
    request.addParameter("related-or-parent1", "");
    request.addParameter("related-or-parent2", "ccc");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-or-child", "");
    request.addParameter("related-or-parent1", "aaa");
    request.addParameter("related-or-parent2", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-or-child", "");
    request.addParameter("related-or-parent1", "");
    request.addParameter("related-or-parent2", "ccc");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-or-child", "aaa");
    request.addParameter("related-or-parent1", "");
    request.addParameter("related-or-parent2", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-or-child", "aaa");
    request.addParameter("related-or-parent1", "");
    request.addParameter("related-or-parent2", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);
  }

  @Test
  public void testEndpointRelatedAndOr() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    // related-and-or-child<related>(related-and-or-parent1:aaa||bbb)||(related-and-or-parent2:ccc||ddd)&&(related-and-or-parent3:eee|fff)</related>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-and-or-child", "aaa");
    request.addParameter("related-and-or-parent1", "aaa");
    request.addParameter("related-and-or-parent2", "ccc");
    request.addParameter("related-and-or-parent3", "eee");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-and-or-child", "");
    request.addParameter("related-and-or-parent1", "");
    request.addParameter("related-and-or-parent2", "");
    request.addParameter("related-and-or-parent3", "eee");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-and-or-child", "");
    request.addParameter("related-and-or-parent1", "aaa");
    request.addParameter("related-and-or-parent2", "ccc");
    request.addParameter("related-and-or-parent3", "eee");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-and-or-child", "");
    request.addParameter("related-and-or-parent1", "");
    request.addParameter("related-and-or-parent2", "ccc");
    request.addParameter("related-and-or-parent3", "eee");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-and-or-child", "");
    request.addParameter("related-and-or-parent1", "");
    request.addParameter("related-and-or-parent2", "");
    request.addParameter("related-and-or-parent3", "eee");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-and-or-child", "");
    request.addParameter("related-and-or-parent1", "aaa");
    request.addParameter("related-and-or-parent2", "");
    request.addParameter("related-and-or-parent3", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-and-or-child", "");
    request.addParameter("related-and-or-parent1", "");
    request.addParameter("related-and-or-parent2", "ccc");
    request.addParameter("related-and-or-parent3", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    // related-and-or-childX<related>(related-and-or-parentX1:aaa||bbb)&&(related-and-or-parentX2:ccc||ddd)||(related-and-or-parentX3:eee||fff)||(related-and-or-parentX4)</related>
    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-and-or-childX", "");
    request.addParameter("related-and-or-parentX1", "bbb");
    request.addParameter("related-and-or-parentX2", "ccc");
    request.addParameter("related-and-or-parentX3", "");
    request.addParameter("related-and-or-parentX4", "");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);
  }

  @Test
  public void testEndpointRelatedRemoveSpace() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    // <related> ( related-and-or-parentY1 : aaa || bbb ) || (
    // related-and-or-parentY2 : ccc || ddd ) && ( related-and-or-parentY3 : eee
    // || fff ) || ( related-and-or-parentY4 : ggg || hhh ) && (
    // related-and-or-parentY5:iii || jjj ) </related>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("related-and-or-childY", "");
    request.addParameter("related-and-or-parentY1", "bbb");
    request.addParameter("related-and-or-parentY2", "ccc");
    request.addParameter("related-and-or-parentY3", "eee");
    request.addParameter("related-and-or-parentY4", "");
    request.addParameter("related-and-or-parentY5", "iii");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

  }

  
  @Test
  public void testEndpointStrictWithLess() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    // related-simple-child<related>related-simple-parent</related>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/strictWithLess.jsp");
    request.addParameter("foobar", "aaa");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);
  }

  @Test
  public void testEndpointStrictTest() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    // related-simple-child<related>related-simple-parent</related>
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/test.jsp");
    request.addParameter("parm1", "aaa");
    request.addParameter("parm2", "aaa");
    boolean isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/strictTrue.jsp");
    request.addParameter("parm1", "aaa");
    request.addParameter("parm2", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/strictTrue.jsp");
    request.addParameter("parm1", "aaa");
    request.addParameter("parm2", "aaa");
    request.addParameter("parm3", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/strictTrue.jsp");
    request.addParameter("parm1", "aaa");
    request.addParameter("parm2", "aaa");
    request.addParameter("parm3", "aaa");
    request.addParameter("parmEXTRA", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/notstrictNoTag.jsp");
    request.addParameter("parm1", "aaa");
    request.addParameter("parm2", "aaa");
    request.addParameter("parm3", "aaa");
    request.addParameter("parmEXTRA", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/notstrictNoTag.jsp");
    request.addParameter("foobar", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/strictWithLess.jsp");
    request.addParameter("parm1", "aaa");
    request.addParameter("parm2", "aaa");
    request.addParameter("parm3", "aaa");
    request.addParameter("parmEXTRA", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/strictWithLess.jsp");
    request.addParameter("parm1", "aaa");
    request.addParameter("parm2", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/strictWithLess.jsp");
    request.addParameter("parm1", "aaa");
    request.addParameter("parm2", "aaa");
    request.addParameter("parm3", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/strictWithLessWord.jsp");
    request.addParameter("parm1", "aaa");
    request.addParameter("parm2", "aaa");
    request.addParameter("parm3", "aaa");
    request.addParameter("parmEXTRA", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertTrue(isThreat);

    request = new MockHttpServletRequest();
    request.setRequestURI("/foo/bar/strictWithLessWord.jsp");
    request.addParameter("parm1", "aaa");
    request.addParameter("parm2", "aaa");
    isThreat = sanwaf.isThreatDetected(request);
    assertFalse(isThreat);
  }

}

