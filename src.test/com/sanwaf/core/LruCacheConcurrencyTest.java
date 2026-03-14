package com.sanwaf.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class LruCacheConcurrencyTest {
  static Sanwaf sanwaf;

  @BeforeAll
  public static void setUpClass() {
    try {
      sanwaf = new Sanwaf(new UnitTestLogger(), "/sanwaf-isThreat.xml");
    } catch (IOException ioe) {
      fail();
    }
  }

  @Test
  public void testConcurrentIsThreatByXml_noCorruption() throws Exception {
    int nThreads = 8;
    int opsPerThread = 200;
    ExecutorService pool = Executors.newFixedThreadPool(nThreads);
    List<Future<?>> futures = new ArrayList<>();
    for (int t = 0; t < nThreads; t++) {
      final int threadId = t;
      futures.add(pool.submit(() -> {
        for (int i = 0; i < opsPerThread; i++) {
          String xml = "<item><name>t" + threadId + "i" + (i % 100) + "</name><type>s</type><max>999</max><min>0</min>" + "<msg></msg><uri></uri></item>";
          Sanwaf.isThreatByXml("safe-value", xml);
        }
      }));
    }
    pool.shutdown();
    assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "threads should complete without hanging (infinite loop from corruption)");
    for (Future<?> f : futures) {
      f.get();
    }
  }
}
