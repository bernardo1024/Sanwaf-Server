package com.sanwaf.core;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class CustomPropertiesFooTest {
  static Sanwaf sanwaf;
  static Shield shield;

  @SuppressWarnings("SpellCheckingInspection")
  @Test
  public void fooXmlResourceTest() {
    try {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-foo.xml");
      shield = UnitTestUtil.getShield(sanwaf, "xss");
    } catch (IOException ioe) {
      fail();
    }

    MockHttpServletRequest req = new MockHttpServletRequest();

    assertFalse(shield.threat(req, shield.parameters, "Numeric", "0123456789"));
    assertTrue(shield.threat(req, shield.parameters, "Numeric", "foo.12"));
    assertTrue(shield.threat(req, shield.parameters, "Numeric", "12.bar"));

    assertFalse(shield.threat(req, shield.parameters, "NumericDelimited", "-12345"));
    assertFalse(shield.threat(req, shield.parameters, "NumericDelimited", "121,23"));
    assertTrue(shield.threat(req, shield.parameters, "NumericDelimited", "+foobar"));
    assertTrue(shield.threat(req, shield.parameters, "NumericDelimited", "123bar"));

    assertFalse(shield.threat(req, shield.parameters, "Alphanumeric", "abcdefghijklmnopqrstuvwxyz0123456789"));
    assertTrue(shield.threat(req, shield.parameters, "Alphanumeric", "1239.a"));

    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMore", "abcde"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMore", "1?234"));
    assertFalse(shield.threat(req, shield.parameters, "AlphanumericAndMore", "1?a1b2c?3d4"));
    assertTrue(shield.threat(req, shield.parameters, "AlphanumericAndMore", "123-456"));
    assertTrue(shield.threat(req, shield.parameters, "AlphanumericAndMore", "123_456"));

    assertFalse(shield.threat(req, shield.parameters, "Char", "a"));
    assertFalse(shield.threat(req, shield.parameters, "Char", "1"));
    assertFalse(shield.threat(req, shield.parameters, "Char", "-"));
    assertFalse(shield.threat(req, shield.parameters, "Char", " "));
    assertFalse(shield.threat(req, shield.parameters, "Char", "12"));
    assertTrue(shield.threat(req, shield.parameters, "Char", "12345"));
    assertTrue(shield.threat(req, shield.parameters, "Char", "<asdffff."));

    assertFalse(shield.threat(req, shield.parameters, "CustomRegexSSN", "555-55-5555"));
    assertTrue(shield.threat(req, shield.parameters, "CustomRegexSSN", "abc-de-fghi"));
    assertTrue(shield.threat(req, shield.parameters, "CustomRegexSSN", "555555555"));

    assertTrue(shield.threat(req, shield.parameters, "CustomRegexSSN", "5555555555"));

    assertFalse(shield.threat(req, shield.parameters, "CustomTel", "555-555-5555"));
    assertFalse(shield.threat(req, shield.parameters, "CustomDate", "2016-01-01"));

    assertTrue(shield.threat(req, shield.parameters, "CustomDate", "2016xxdd"));
    assertTrue(shield.threat(req, shield.parameters, "CustomTel", "55-555-55556"));

    assertTrue(shield.threat(req, shield.parameters, "fooaFoo", "abcdefghi"));
    assertTrue(shield.threat(req, shield.parameters, "foobFoo", "abcdefghi"));
    assertTrue(shield.threat(req, shield.parameters, "foocFoo", "abcdefghi"));
    assertTrue(shield.threat(req, shield.parameters, "foodFoo", "abcdefghi"));
    assertTrue(shield.threat(req, shield.parameters, "fooeFoo", "abcdefghi"));
    assertTrue(shield.threat(req, shield.parameters, "foofFoo", "abcdefghi"));

    assertFalse(shield.threat(req, shield.parameters, "fooaFoo", "12345,67890"));
    assertFalse(shield.threat(req, shield.parameters, "foobFoo", "12345,67890"));
    assertFalse(shield.threat(req, shield.parameters, "foocFoo", "12345,67890"));
    assertFalse(shield.threat(req, shield.parameters, "foodFoo", "12345,67890"));
    assertFalse(shield.threat(req, shield.parameters, "fooeFoo", "12345,67890"));
    assertFalse(shield.threat(req, shield.parameters, "foofFoo", "12345,67890"));

    assertFalse(shield.threat(req, shield.parameters, "*foo", "<script>alert(1)</script>"));
  }
}
