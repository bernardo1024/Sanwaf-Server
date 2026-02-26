package com.sanwaf.core;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class RelatedErrMsgThreadSafetyTest
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
  public void testRelatedErrMsgIsNotSharedAcrossThreads() throws Exception
  {
    int threadCount = 20;
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    CountDownLatch startLatch = new CountDownLatch(1);
    CountDownLatch doneLatch = new CountDownLatch(threadCount);
    AtomicInteger failures = new AtomicInteger(0);

    for (int i = 0; i < threadCount; i++)
    {
      final int threadId = i;
      executor.submit(() ->
      {
        try
        {
          startLatch.await();
          MockHttpServletRequest req = new MockHttpServletRequest();
          req.setRequestURI("/foo/bar/test.jsp");
          req.addParameter("related-equals-child", "child-" + threadId);
          req.addParameter("related-equals-parent", "parent-" + threadId);
          boolean threat = sanwaf.isThreatDetected(req);
          if (!threat)
          {
            failures.incrementAndGet();
            return;
          }
          String errors = Sanwaf.getErrors(req);
          if (errors == null || !errors.contains("child-" + threadId) || !errors.contains("does not match"))
          {
            failures.incrementAndGet();
          }
        }
        catch (Exception e)
        {
          failures.incrementAndGet();
        }
        finally
        {
          doneLatch.countDown();
        }
      });
    }
    startLatch.countDown();
    assertTrue("Timed out waiting for threads", doneLatch.await(10, TimeUnit.SECONDS));
    executor.shutdown();
    assertEquals(0, failures.get());
  }

  @Test
  public void testRelatedErrMsgDoesNotLeakToSubsequentCleanRequests()
  {
    // First: trigger a related error (mismatched values)
    MockHttpServletRequest req1 = new MockHttpServletRequest();
    req1.setRequestURI("/foo/bar/test.jsp");
    req1.addParameter("related-equals-child", "aaa");
    req1.addParameter("related-equals-parent", "bbb");
    assertTrue(sanwaf.isThreatDetected(req1));

    // Second: send a clean request with matching values (no error expected)
    MockHttpServletRequest req2 = new MockHttpServletRequest();
    req2.setRequestURI("/foo/bar/test.jsp");
    req2.addParameter("related-equals-child", "same");
    req2.addParameter("related-equals-parent", "same");
    assertFalse(sanwaf.isThreatDetected(req2));
    assertNull(req2.getAttribute(Sanwaf.ATT_LOG_ERROR));
  }

  @Test
  public void testRelatedErrMsgInDetectMode()
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setRequestURI("/foo/bar/test.jsp");
    req.addParameter("related-detect-child", "abc");
    req.addParameter("related-detect-parent", "xyz");
    assertFalse(sanwaf.isThreatDetected(req));
    String detects = Sanwaf.getDetects(req);
    assertNotNull(detects);
    assertTrue(detects.contains("does not match"));
    assertNull(Sanwaf.getErrors(req));
  }
}
