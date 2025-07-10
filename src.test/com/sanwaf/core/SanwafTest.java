package com.sanwaf.core;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.springframework.mock.web.MockHttpServletRequest;

import com.sanwaf.core.Shield;
import com.sanwaf.core.Sanwaf;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SanwafTest {
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
  public void testXssNoThreat() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("String", "abcdefghij");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(false));
  }

  @Test
  public void testXssWithThreat() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter("String", "<script>alert(1);</script>");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(true));
  }

  @Test
  public void testTrackIdAndGetErrorsNumbersDelimited() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.addParameter("NumericDelimited", "+foobar");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(true));

    String trackId = Sanwaf.getTrackingId(request);
    assertTrue(trackId != null);

    String s = Sanwaf.getErrors(request);
    assertTrue(s.indexOf("{\"name\":\"NumericDelimited\",") >= 0);

    s = Sanwaf.getDetects(request);
    assertTrue(s == null || s.length() == 0);
  }

  @Test
  public void testTrackIdAndGetErrorsAlphanumericAndMore() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.addParameter("AlphanumericAndMore", "Some Bad! data;----?? ");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(true));

    String trackId = Sanwaf.getTrackingId(request);
    assertTrue(trackId != null);

    String s = Sanwaf.getErrors(request);
    assertTrue(s.indexOf("{\"name\":\"AlphanumericAndMore\"") >= 0);
  }

  @Test
  public void testTrackIdDisabled() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.addParameter("NumericDelimited", "+foobar");
    boolean trackID = sanwaf.onErrorAddTrackId;
    boolean trackErrors = sanwaf.onErrorAddParmErrors;
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(true));
    assertTrue(Sanwaf.getTrackingId(request) != null);
    String s = Sanwaf.getErrors(request);
    assertTrue(s != null);

    sanwaf.onErrorAddTrackId = false;
    sanwaf.onErrorAddParmErrors = false;
    request = new MockHttpServletRequest();
    request.addParameter("NumericDelimited", "+foobar");
    result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(true));
    assertTrue(Sanwaf.getTrackingId(request) == null);
    s = Sanwaf.getErrors(request);
    System.out.println("**********"+s);
    assertTrue(s == null);

    sanwaf.onErrorAddTrackId = trackID;
    sanwaf.onErrorAddParmErrors = trackErrors;
  }

  @Test
  public void testSanwafReload() {
    try {
      Sanwaf sw = new Sanwaf();
      assertTrue(sw != null);
      sw.reLoad();
      assertTrue(sw != null);
    } catch (IOException ioe) {
    }
  }

  @Test
  public void testSanwafInstatiateLoggerOnly() {
    try {
      Sanwaf sw = new Sanwaf(new com.sanwaf.log.SimpleLogger());
      assertTrue(sw != null);
      sw.reLoad();
    } catch (IOException ioe) {
    }
  }

  @Test
  public void testSanwafInstantiate() {
    try {
      Sanwaf sw = new Sanwaf();
      assertTrue(sw != null);
      sw.reLoad();
    } catch (IOException ioe) {
    }
  }

  @Test
  public void testSanWafInvalidXML() {
    try {
      new Sanwaf(new UnitTestLogger(), "invalidXmlFilename.foobar");
      fail("Error, Sanwaf instanciated with invalid xml file");
    } catch (IOException ioe) {
      assertTrue(ioe instanceof IOException);
    }
  }

  @Test
  public void testSanWafLoggerAndFile() {
    try {
      Sanwaf sw = new Sanwaf(new UnitTestLogger(), "/sanwaf.xml");
      assertTrue(sw != null);
    } catch (IOException ioe) {
      fail("exception Raised");
    }
  }

  @Test
  public void TestNonMappedParamDefaultToStingWithRegexAlwaysEnabled() {
    boolean xssAlways = shield.regexAlways;
    shield.regexAlways = true;
    boolean b = sanwaf.isThreatDetected(null);
    assertFalse(b);

    MockHttpServletRequest request = new MockHttpServletRequest();
    request = new MockHttpServletRequest();
    request.addParameter("foobarTHISisNOTmappedXssError", "<script>alert(1)</script>");
    Boolean result = sanwaf.isThreatDetected(request);
    assertTrue(result.equals(true));

    shield.regexAlways = xssAlways;
  }
}

