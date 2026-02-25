package com.sanwaf.core;

import org.springframework.mock.web.MockHttpServletRequest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class UnitTestUtil
{

  public static void log(String title, UnitTestResult result)
  {
    if (result == null)
    {
      System.out.println(title + " - error; result is null.");
    }
    else
    {
      System.out.println(title + "\t#pass:\t" + result.pass + "\t#fail:\t" + result.fail + "\tin:\t" + result.getTestTime() + "\tper:\t" + result.getAvgTime());

      if (result.errors != null && result.errors.length() > 0)
      {
        System.out.println(title + " ERRORS:\n" + result.errors);
      }
    }
  }

  static Shield getShield(Sanwaf sanwaf, String name)
  {
    for (Shield shield : sanwaf.shields)
    {
      if (shield.name.equalsIgnoreCase(name))
      {
        return shield;
      }
    }
    return null;
  }

  static UnitTestResult runTestsUsingFile(Shield shield, String filename, int iterations, boolean doHex, boolean logErrors)
  {
    UnitTestResult result = new UnitTestResult();
    String file = UnitTestUtil.readFile(filename);
    if (file.isEmpty())
    {
      return null;
    }

    file = file.replace("\r", "");
    String[] lines = file.split("\n");

    List<String[]> lineArrays = new ArrayList<>();
    for (String line : lines)
    {
      if (!line.startsWith("#"))
      {
        String[] data = line.split("\t\t");
        if (data.length == 3)
        {
          lineArrays.add(data);
        }
      }
    }

    result.start();
    for (int i = 0; i < iterations; i++)
    {
      for (String[] data : lineArrays)
      {
        if (doHex)
        {
          testAllHexPermutations(shield, result, data[0], data[2], Boolean.parseBoolean(data[1]), logErrors);
        }
        else
        {
          boolean runMultiple = data[2].startsWith("#");
          if (runMultiple)
          {
            data[2] = data[2].substring(1);
          }
          runTests(shield, result, data[0], data[2], Boolean.parseBoolean(data[1]), runMultiple, logErrors);
        }
      }
    }
    result.end();
    return result;
  }

  static void testAllHexPermutations(Shield shield, UnitTestResult result, String parmName, String payload, boolean expected, boolean logError)
  {
    if (payload == null || payload.isEmpty())
    {
      return;
    }
    boolean runMultiple = payload.startsWith("#");
    if (runMultiple)
    {
      payload = payload.substring(1);
    }
    int len = payload.length();
    for (int block = 0; block <= len + 1; block++)
    {
      for (int pos = 0; pos < (len - block + 1); pos++)
      {
        String start = payload.substring(0, pos);
        String middle = getHexValueOfString(payload.substring(pos, pos + block));
        String end = payload.substring(pos + block);
        runTests(shield, result, parmName, start + middle + end, expected, runMultiple, logError);
        if (block == 0)
        {// block 0 is un-altered payload already run
          break;
        }
      }
    }
  }

  private static void runTests(Shield shield, UnitTestResult result, String parameterName, String payload, boolean expected, boolean runMultiple, boolean logError)
  {
    if (runMultiple)
    {
      runTest(shield, result, parameterName, "<word " + payload + "=", expected, logError);
      runTest(shield, result, parameterName, getHexValueOfString("<") + "word " + payload + "=", expected, logError);
      runTest(shield, result, parameterName, getHexValueOfString("<") + "word " + payload + getHexValueOfString("="), expected, logError);
      runTest(shield, result, parameterName, "<" + "word " + payload + getHexValueOfString("="), expected, logError);
      runTest(shield, result, parameterName, "\"" + payload + "=", expected, logError);
      runTest(shield, result, parameterName, getHexValueOfString("\"") + payload + "=", expected, logError);
      runTest(shield, result, parameterName, getHexValueOfString("\"") + payload + getHexValueOfString("="), expected, logError);
      runTest(shield, result, parameterName, "\"" + payload + getHexValueOfString("="), expected, logError);
      runTest(shield, result, parameterName, "'" + payload + "=", expected, logError);
      runTest(shield, result, parameterName, getHexValueOfString("'") + payload + "=", expected, logError);
      runTest(shield, result, parameterName, getHexValueOfString("'") + payload + getHexValueOfString("="), expected, logError);
      runTest(shield, result, parameterName, "'" + payload + getHexValueOfString("="), expected, logError);
    }
    else
    {
      runTest(shield, result, parameterName, payload, expected, logError);
    }
  }

  private static void runTest(Shield shield, UnitTestResult result, String parameterName, String payload, boolean expected, boolean logError)
  {
    MockHttpServletRequest req = new MockHttpServletRequest();
    boolean retval = shield.threat(req, shield.parameters, parameterName, payload, false, false);
    if (retval != expected)
    {
      if (logError)
      {
        result.errors.append(parameterName + "\t" + payload + "\n");
      }
      result.fail++;
    }
    else
    {
      result.pass++;
    }
  }

  static String getHexValueOfString(String s)
  {
    StringBuilder sb = new StringBuilder();
    char[] chars = s.toCharArray();
    for (char c : chars)
    {
      sb.append("%").append(Integer.toHexString(c));
    }
    return sb.toString();
  }

  static String parseFolderName(String s)
  {
    int i = s.lastIndexOf(File.separator);
    if (i < 0)
    {
      // see if this is the other separator
      if (File.separator.equals("\\"))
      {
        i = s.lastIndexOf("/");
      }
      else
      {
        i = s.lastIndexOf("\\");
      }
    }
    return s.substring(0, i);
  }

  static String readFile(String s)
  {
    FileInputStream fis = null;
    try
    {
      File f = new File(s);
      if (!f.exists())
      {
        return "";
      }
      int size = (int) f.length();
      int read = 0;
      fis = new FileInputStream(s);
      byte[] bytes = new byte[size];
      while (read < size)
      {
        read += fis.read(bytes, read, size - read);
      }
      fis.close();
      return new String(bytes);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    finally
    {
      safeClose(fis);
    }
    return "";
  }

  public static void writeFile(String data, String s)
  {
    try
    {
      String dir = s;
      int i_pos = s.lastIndexOf(File.separator);
      if (i_pos > 0)
      {
        dir = dir.substring(0, i_pos);
        if (!dir.trim().isEmpty() && !dir.equals("."))
        {
          File f = new File(dir);
          if (!f.exists())
          {
            f.mkdirs();
          }
          f = null;
        }
      }
      OutputStream os = new FileOutputStream(s);
      os.write(data.getBytes());
      os.close();
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }

  public static void safeClose(FileInputStream fis)
  {
    if (fis != null)
    {
      try
      {
        fis.close();
      }
      catch (IOException e)
      {
        e.printStackTrace();
      }
    }
  }
}

