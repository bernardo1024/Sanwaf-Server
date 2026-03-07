package com.sanwaf.core;

import jakarta.servlet.ServletRequest;

import java.util.ArrayList;
import java.util.List;

/**
 * Validates inter-parameter relationships defined in Sanwaf configuration.
 *
 * <p>Related-field expressions use a small DSL with AND ({@code &&}) and OR
 * ({@code ||}) operators, optional value constraints ({@code param:val1||val2}),
 * and an equality shorthand ({@code param:=}). This class parses those
 * expressions into {@link Block} arrays and evaluates them against the
 * current request.
 *
 * <p>All methods are static; instantiation is not permitted.
 */
final class RelationValidator {

  /** Prevents instantiation. */
  private RelationValidator() {
  }

  /**
   * Represents a single condition block within a related-field expression.
   *
   * <p>A block references a parent parameter by name and optionally a set of
   * acceptable values. The {@code isAnd} flag indicates whether this block is
   * joined to the previous block with an AND operator (as opposed to OR).
   */
  static final class Block {
    /** The name of the related request parameter. */
    final String paramName;
    /** Acceptable values for the parent parameter, or {@code null} if any non-empty value suffices. */
    final String[] orValues;
    /** {@code true} if this block is combined with the previous block via AND. */
    final boolean isAnd;

    /**
     * Constructs a condition block.
     *
     * @param paramName the related parameter name
     * @param orValues  acceptable values, or {@code null} for a presence check
     * @param isAnd     {@code true} if this block uses AND logic
     */
    Block(String paramName, String[] orValues, boolean isAnd) {
      this.paramName = paramName;
      this.orValues = orValues;
      this.isAnd = isAnd;
    }

    /**
     * Evaluates this block against the current request.
     *
     * <p>If {@code orValues} is non-null the parent parameter must equal one
     * of the listed values. Otherwise the block evaluates to {@code true} when
     * the parent has a non-empty value and the current item's value is empty
     * (i.e. the item is required but missing).
     *
     * @param req   the current servlet request
     * @param value the current item's parameter value
     * @return {@code true} if the condition is satisfied
     */
    boolean evaluate(ServletRequest req, String value) {
      String parentValue = req.getParameter(paramName);
      if (orValues != null) {
        for (String or : orValues) {
          if (or.equals(parentValue)) {
            return true;
          }
        }
        return false;
      }
      return parentValue != null && !parentValue.isEmpty() && value.isEmpty();
    }
  }

  /**
   * Parses a related-field expression into an array of {@link Block}s.
   *
   * @param related the raw related-field expression from configuration
   * @return the parsed blocks, or {@code null} if the expression is empty,
   *         {@code null}, or ends with {@code ":="} (equality shorthand)
   */
  static Block[] parseRelation(String related) {
    if (related == null || related.isEmpty() || related.endsWith(":=")) {
      return null;
    }
    List<String> andBlocks = parseBlocks(related, 0, "AND", ")&&(", "(", ")");
    List<String> andOrBlocks = parseOrBlocksFromAndBlocks(andBlocks);
    List<Block> result = new ArrayList<>();
    boolean nextIsAnd = false;
    for (String entry : andOrBlocks) {
      if ("AND".equals(entry)) {
        nextIsAnd = true;
        continue;
      }
      if ("OR".equals(entry)) {
        nextIsAnd = false;
        continue;
      }
      int colon = entry.indexOf(':');
      String paramName = (colon >= 0) ? entry.substring(0, colon) : entry;
      String[] orValues = (colon >= 0) ? splitOnDoublePipe(entry, colon + 1) : null;
      result.add(new Block(paramName, orValues, nextIsAnd));
      nextIsAnd = false;
    }
    return result.toArray(new Block[0]);
  }

  /**
   * Validates a parameter value against its related-field expression.
   *
   * @param blocks  pre-parsed condition blocks (may be {@code null} for
   *                equality-shorthand expressions)
   * @param related the raw related-field expression
   * @param value   the current parameter value
   * @param req     the current servlet request
   * @param meta    metadata providing access to other configured items
   * @return an error message string if validation fails, or {@code null} if
   *         the value is valid
   */
  static String validate(Block[] blocks, String related, String value, ServletRequest req, Metadata meta) {
    if (related == null || related.isEmpty()) {
      return null;
    }
    if (related.endsWith(":=")) {
      return isRelatedEqual(related, value, req, meta);
    }

    int andTrueCount = 0;
    int andTotalCount = 0;
    boolean orFoundTrue = false;
    for (Block block : blocks) {
      boolean condResult = block.evaluate(req, value);
      if (block.isAnd) {
        andTotalCount++;
        if (condResult) {
          andTrueCount++;
        }
      } else if (condResult) {
        orFoundTrue = true;
      }
    }
    if (andTrueCount == andTotalCount && orFoundTrue && value.isEmpty()) {
      return buildRequiredMessage(related, meta);
    }
    return null;
  }

  /**
   * Builds a human-readable "required" error message derived from the
   * related-field expression.
   *
   * @param related the raw related-field expression
   * @param meta    metadata for resolving display names
   * @return the error message fragment
   */
  private static String buildRequiredMessage(String related, Metadata meta) {
    String raw = related;
    int paren = raw.indexOf('(');
    if (paren >= 0) {
      int end = raw.indexOf(')', paren);
      if (end > paren) {
        raw = raw.substring(paren + 1, end);
      }
    }
    int colon = raw.indexOf(':');
    String parentName = (colon > 0) ? raw.substring(0, colon).trim() : raw.trim();

    Item parentItem = meta.getItem(parentName);
    String parentDisplay = (parentItem != null) ? parentItem.display : parentName;
    if (related.contains("&&")) {
      return " - required based on related field conditions";
    }
    return " - required when \"" + parentDisplay + "\" has a value";
  }

  /**
   * Splits already-parsed AND blocks into individual OR sub-blocks and
   * normalises delimiters into {@code "AND"} and {@code "OR"} sentinel
   * strings.
   *
   * @param andBlocks the list of AND-separated block strings
   * @return a flat list of block strings interspersed with {@code "AND"} /
   *         {@code "OR"} sentinels
   */
  private static List<String> parseOrBlocksFromAndBlocks(List<String> andBlocks) {
    List<String> andOrBlocks = new ArrayList<>();
    List<String> blocks;
    for (String andBlock : andBlocks) {
      blocks = parseBlocks(andBlock, 0, "OR", ")||(", "(", ")");
      for (int j = 0; j < blocks.size(); j++) {
        if (blocks.get(j).equals("||")) {
          blocks.set(j, "OR");
        } else if (blocks.get(j).endsWith(")||")) {
          String block = blocks.get(j);
          blocks.set(j, block.substring(1, block.length() - 3));
          blocks.add(j + 1, "OR");
        }
      }
      andOrBlocks.addAll(blocks);
    }
    return andOrBlocks;
  }

  /**
   * Handles the equality-shorthand ({@code param:=}) by comparing the
   * current value to the related parameter's value.
   *
   * @param related the raw related expression ending with {@code ":="}
   * @param value   the current parameter value
   * @param req     the current servlet request
   * @param meta    metadata for resolving the parent item's display name
   * @return an error message if the values differ, or {@code null} if they
   *         match (or the parent item is not configured)
   */
  private static String isRelatedEqual(String related, String value, ServletRequest req, Metadata meta) {
    int colon = related.indexOf(':');
    String parentName = related.substring(0, colon);
    String parentValue = req.getParameter(parentName);
    if (value.equals(parentValue)) {
      return null;
    }
    Item parentItem = meta.getItem(parentName);
    return parentItem == null ? null : " - does not match \"" + parentItem.display + "\"";
  }

  /**
   * Splits a substring of {@code s} starting at {@code from} on the
   * {@code "||"} delimiter.
   *
   * @param s    the full string
   * @param from the index to start splitting from
   * @return an array of substrings between {@code "||"} delimiters
   */
  private static String[] splitOnDoublePipe(String s, int from) {
    int count = 1;
    for (int p = s.indexOf("||", from); p >= 0; p = s.indexOf("||", p + 2)) {
      count++;
    }
    String[] parts = new String[count];
    int i = 0;
    int start = from;
    int pos;
    while ((pos = s.indexOf("||", start)) >= 0) {
      parts[i++] = s.substring(start, pos);
      start = pos + 2;
    }
    parts[i] = s.substring(start);
    return parts;
  }

  /**
   * Splits a related-field expression string into blocks separated by the
   * given logical operator pattern.
   *
   * @param s            the expression string to parse
   * @param start        the index to begin parsing from
   * @param andOr        the sentinel string to insert between blocks
   *                     ({@code "AND"} or {@code "OR"})
   * @param match        the delimiter pattern to search for
   *                     (e.g. {@code ")&&("} or {@code ")||(")
   * @param reverseMatch the opening bracket pattern used to find the block
   *                     start before the delimiter
   * @param forwardMatch the closing bracket pattern used to find the block
   *                     end after the delimiter
   * @return a list of block strings interspersed with {@code andOr} sentinels
   */
  private static List<String> parseBlocks(String s, int start, String andOr, String match, String reverseMatch, String forwardMatch) {
    List<String> blocks = new ArrayList<>();
    int lastPos = start;
    while (true) {
      int pos = s.indexOf(match, lastPos);
      if (pos > 0) {
        start = s.lastIndexOf(reverseMatch, pos);
        if (start != lastPos) {
          blocks.add(s.substring(lastPos, start));
        }
        blocks.add(s.substring(start + reverseMatch.length(), pos));
        blocks.add(andOr);
        int end = s.indexOf(forwardMatch, pos + match.length());
        blocks.add(s.substring(pos + match.length(), end));
        lastPos = end + forwardMatch.length();
      } else {
        if (lastPos + 1 < s.length()) {
          blocks.add(s.substring(lastPos));
        }
        break;
      }
    }
    return blocks;
  }
}
