package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.MethodOrderer;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@TestMethodOrder(MethodOrderer.MethodName.class)
public class MultiDimentionalyParmsTest
{
  static Sanwaf sanwaf;
  static Shield shield;

  @BeforeAll
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-multiDim.xml");
      shield = UnitTestUtil.getShield(sanwaf, "MultiDimTest");
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testVariablenumericDelimited()
  {
    MockHttpServletRequest r = new MockHttpServletRequest();
    r.addParameter("a['1'].b['2']", "1234567890,0987654321");
    assertFalse(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("a['1'].b['2']", "12345678901,10987654321");
    assertTrue(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("a['1'].b['2']", "123456789,987654321");
    assertTrue(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("a['1'].b['2']", "12345678.a,a.87654321");
    assertTrue(sanwaf.isThreatDetected(r));
  }

  @Test
  public void testVariablenumeric()
  {
    MockHttpServletRequest r = new MockHttpServletRequest();
    r.addParameter("b[1].c[2]", "1234567890");
    assertFalse(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("b[1].c[2]", "12345678901");
    assertTrue(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("b[1].c[2]", "12345");
    assertTrue(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("b[1].c[2]", "12345678.a");
    assertTrue(sanwaf.isThreatDetected(r));
  }

  @Test
  public void testVariablenumeric2()
  {
    MockHttpServletRequest r = new MockHttpServletRequest();
    r.addParameter("foo1", "1234567890");
    assertFalse(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("foo2", "12345678901");
    assertFalse(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("foo111", "<script>");
    assertTrue(sanwaf.isThreatDetected(r));
  }

  @Test
  public void testVariableAlphanumericAndMore()
  {
    MockHttpServletRequest r = new MockHttpServletRequest();
    r.addParameter("c('1').d('2')", "12345,abcd");
    assertFalse(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("c('1').d('2')", "12345abcd,000");
    assertTrue(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("c('1').d('2')", "12345a");
    assertTrue(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("c('1').d('2')", "12345,abc&");
    assertTrue(sanwaf.isThreatDetected(r));
  }

  @Test
  public void testVariableAlpahnumeric()
  {
    // <item>d(*).e(*)=a(6,10)</item>
    MockHttpServletRequest r = new MockHttpServletRequest();
    r.addParameter("d(1).e(2)", "12345abcde");
    assertFalse(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("d(1).e(2)", "12345abcd000");
    assertTrue(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("d(1).e(2)", "1234a");
    assertTrue(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("d(1).e(2)", "12345abc&");
    assertTrue(sanwaf.isThreatDetected(r));
  }

  @Test
  public void testVariableChar()
  {
    MockHttpServletRequest r = new MockHttpServletRequest();
    r.addParameter("e[1].f[2]g(3)-h(4)", "1");
    assertFalse(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("e[1].f[2]g(3)-h(4)", "12345abcd000");
    assertTrue(sanwaf.isThreatDetected(r));
  }

  @Test
  public void testVariableNotDefined()
  {
    MockHttpServletRequest r = new MockHttpServletRequest();
    r.addParameter("notdefined[1]", "<script>alert(1)</script>");
    assertFalse(sanwaf.isThreatDetected(r));

    r = new MockHttpServletRequest();
    r.addParameter("notDefinedNoBrackets1", "<script>alert(1)</script>");
    assertTrue(sanwaf.isThreatDetected(r));
  }

  @Test
  public void testVariablenumericInvalidFormat()
  {
    MockHttpServletRequest r = new MockHttpServletRequest();
    r.addParameter("foo((0)", "1234567890");
    r.addParameter("foo[[0]", "1234567890");
    r.addParameter("foo( 0)", "1234567890");
    r.addParameter("foo(0 )", "1234567890");
    assertFalse(sanwaf.isThreatDetected(r));
  }

  @Test
  public void testVariablenumericArray()
  {
    MockHttpServletRequest r = new MockHttpServletRequest();
    r.addParameter("foo0", "1234567890");
    r.addParameter("foo1", "1234567890");
    r.addParameter("foo2", "1234567890");
    r.addParameter("foo3", "1234567890");
    r.addParameter("foo4", "1234567890");
    r.addParameter("foo5", "1234567890");
    r.addParameter("foo6", "1234567890");
    r.addParameter("foo7", "1234567890");
    r.addParameter("foo8", "1234567890");
    r.addParameter("foo9", "1234567890");
    r.addParameter("foo10", "1234567890");
    assertFalse(sanwaf.isThreatDetected(r));
  }

  @Test
  public void testInvalidArray() throws IOException
  {
    Sanwaf sw = new Sanwaf(new UnitTestLogger(), "/sanwaf-multiDim.xml");
    Shield sh = UnitTestUtil.getShield(sw, "MultiDimTest");
    assertNotNull(sh);
    Metadata meta = new Metadata(shield, new Xml(""), "", sw.logger);
    UnitTestUtil.setField(meta, "enabled", true);
    Map<String, Set<String>> mutableIndex = new HashMap<>();
    Set<String> fooSet = new LinkedHashSet<>();
    fooSet.add(Metadata.INDEX_PARM_MARKER + "foo");
    mutableIndex.put("f", fooSet);
    UnitTestUtil.setField(meta, "index", Collections.unmodifiableMap(mutableIndex));
    UnitTestUtil.setField(sh, "parameters", meta);

    MockHttpServletRequest r = new MockHttpServletRequest();
    r.addParameter("foo0", "<script>alert(1)</script>");
    assertFalse(sw.isThreatDetected(r));
  }

}

