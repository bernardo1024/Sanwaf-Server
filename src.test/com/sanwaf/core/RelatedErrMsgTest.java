package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class RelatedErrMsgTest
{
  static Sanwaf sanwaf;

  @BeforeClass
  public static void setUpClass()
  {
    try
    {
      sanwaf = new Sanwaf();
    }
    catch (IOException ioe)
    {
      fail();
    }
  }

  @Test
  public void testSimpleRelatedErrMsgContainsParentName()
  {
    // related-simple-child <related>related-simple-parent</related>
    // parent has value, child empty => threat with "required when" message
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/test.jsp");
    req.addParameter("related-simple-child", "");
    req.addParameter("related-simple-parent", "aaa");
    assertTrue(sanwaf.isThreatDetected(req));
    String errors = Sanwaf.getErrors(req);
    assertNotNull(errors);
    assertTrue(errors.contains("required when"));
    assertTrue(errors.contains("related-simple-parent"));
  }

  @Test
  public void testSimpleOrRelatedErrMsgContainsParentName()
  {
    // related-simple-or-child <related>related-simple-or-parent:aaa||bbb</related>
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/test.jsp");
    req.addParameter("related-simple-or-child", "");
    req.addParameter("related-simple-or-parent", "aaa");
    assertTrue(sanwaf.isThreatDetected(req));
    String errors = Sanwaf.getErrors(req);
    assertNotNull(errors);
    assertTrue(errors.contains("required when"));
    assertTrue(errors.contains("related-simple-or-parent"));
  }

  @Test
  public void testOrRelatedErrMsgContainsParentName()
  {
    // related-or-child <related>(related-or-parent1:aaa||bbb)||(related-or-parent2:ccc||ddd)</related>
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/test.jsp");
    req.addParameter("related-or-child", "");
    req.addParameter("related-or-parent1", "aaa");
    req.addParameter("related-or-parent2", "");
    assertTrue(sanwaf.isThreatDetected(req));
    String errors = Sanwaf.getErrors(req);
    assertNotNull(errors);
    assertTrue(errors.contains("required when"));
    assertTrue(errors.contains("related-or-parent1"));
  }

  @Test
  public void testAndOrRelatedErrMsgShowsGenericMessage()
  {
    // related-and-or-child <related>(related-and-or-parent1:aaa||bbb)||(related-and-or-parent2:ccc||ddd)&&(related-and-or-parent3:eee||fff)</related>
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/test.jsp");
    req.addParameter("related-and-or-child", "");
    req.addParameter("related-and-or-parent1", "aaa");
    req.addParameter("related-and-or-parent2", "ccc");
    req.addParameter("related-and-or-parent3", "eee");
    assertTrue(sanwaf.isThreatDetected(req));
    String errors = Sanwaf.getErrors(req);
    assertNotNull(errors);
    assertTrue(errors.contains("required based on related field conditions"));
  }

  @Test
  public void testNoThreatProducesNoErrMsg()
  {
    // child has a value => no threat, no error
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/test.jsp");
    req.addParameter("related-simple-child", "aaa");
    req.addParameter("related-simple-parent", "aaa");
    assertFalse(sanwaf.isThreatDetected(req));
    assertNull(Sanwaf.getErrors(req));
  }

  @Test
  public void testParentValueRelatedErrMsgContainsParentName()
  {
    // related-simple-or-no-parent-child <related>related-simple-or-no-parent-parent:Yes</related>
    // parent equals "Yes", child empty => threat
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/test.jsp");
    req.addParameter("related-simple-or-no-parent-child", "");
    req.addParameter("related-simple-or-no-parent-parent", "Yes");
    assertTrue(sanwaf.isThreatDetected(req));
    String errors = Sanwaf.getErrors(req);
    assertNotNull(errors);
    assertTrue(errors.contains("required when"));
    assertTrue(errors.contains("related-simple-or-no-parent-parent"));
  }
}
