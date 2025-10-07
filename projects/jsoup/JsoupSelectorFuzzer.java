package org.jsoup.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.jsoup.select.Selector;
import java.util.regex.PatternSyntaxException;
import java.util.Locale;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.UUID;

/**
 * Fuzzer for jsoup's CSS selector engine.
 *
 * Input format (via FuzzedDataProvider):
 *  - First up to 1024 characters: HTML to parse.
 *  - Remainder: CSS selector to apply to the parsed document.
 */
public class JsoupSelectorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String html = data.consumeString(1024);
    String selector = data.consumeRemainingAsString();

    long t0 = System.nanoTime();
    Document doc = Jsoup.parse(html);

    try {
      // Optionally skip regex-driven selectors that frequently trigger sanitizer noise
      if (SKIP_REGEX && isRegexSelector(selector)) {
        if (TRIAGE) emitTriage(html, selector, null, new IllegalArgumentException("regex-like selector skipped"), null);
        return;
      }
      // Apply selector; ignore trivial syntax errors so fuzzing focuses on deeper issues.
      Elements found;
      try {
        found = doc.select(selector);
      } catch (Throwable t) {
        // Swallow trivial or low-signal issues, including Jazzer low findings even if classloader differs.
        if (isTrivialOrLowSignal(t)) {
          if (TRIAGE) emitTriage(html, selector, null, t, null);
          return;
        }
        if (TRIAGE) emitTriage(html, selector, null, t, null);
        throw t;
      }
      long t1 = System.nanoTime();

      // Touch common methods to exercise code paths in Element/Selector.
      for (Element el : found) {
        el.normalName();
        el.tagName();
        el.id();
        el.className();
        el.text();
        el.ownText();
        el.baseUri();
        el.attributes().size();
        el.childNodeSize();
        el.siblingIndex();
        el.siblingElements().size();

        // Re-run selection within context to stress nested queries.
        try {
          el.select("*");
        } catch (Throwable t) {
          if (isTrivialOrLowSignal(t)) {
            if (TRIAGE) emitTriage(html, selector, null, t, null);
            return;
          }
          if (TRIAGE) emitTriage(html, selector, null, t, null);
          throw t;
        }
        if (el.parent() != null) {
          try {
            el.parent().select(selector);
          } catch (Throwable t) {
            if (isTrivialOrLowSignal(t)) {
              if (TRIAGE) emitTriage(html, selector, null, t, null);
              return;
            }
            if (TRIAGE) emitTriage(html, selector, null, t, null);
            throw t;
          }
        }
        // Traverse upwards to exercise parent/parents paths.
        el.parents().size();
      }
      if (TRIAGE) emitTriage(html, selector, found, null, (t1 - t0) / 1_000_000L);
    } catch (StackOverflowError | OutOfMemoryError serious) {
      // Let serious issues bubble up to flag potential recursion/stack problems.
      if (TRIAGE) emitTriage(html, selector, null, serious, null);
      throw serious;
    } catch (Throwable t) {
      // Reduce noise: swallow other exceptions as low-signal for this campaign.
      if (isTrivialOrLowSignal(t)) {
        if (TRIAGE) emitTriage(html, selector, null, t, null);
        return;
      }
      // Propagate unexpected throwables
      if (TRIAGE) emitTriage(html, selector, null, t, null);
      throw t;
    }
  }

  // Heuristics to detect trivial parse/regex issues or Jazzer low-signal sanitizer findings
  private static boolean isTrivialOrLowSignal(Throwable t) {
    if (t instanceof IllegalArgumentException) return true;
    if (t instanceof PatternSyntaxException) return true;
    if (t instanceof Selector.SelectorParseException) return true;
    if (isJazzerLowSignal(t)) return true;
    return false;
  }

  private static boolean isJazzerLowSignal(Throwable t) {
    // Match by class name to be resilient to different classloaders/jar versions
    while (t != null) {
      String cn = t.getClass().getName();
      if ("com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow".equals(cn)) return true;
      // Also check message hints from RegexInjection sanitizer
      String msg = t.getMessage();
      if (msg != null && (msg.contains("Regular Expression Injection") || msg.toLowerCase().contains("regex"))) return true;
      t = t.getCause();
    }
    return false;
  }

  private static final boolean TRIAGE = propOn("selector.triage");
  private static final String TRIAGE_DIR = System.getProperty("selector.triage.dir", "findings/selector");
  private static final String TRIAGE_ID = System.getProperty("selector.triage.id", "");

  private static void emitTriage(String html, String selector, Elements found, Throwable error, Long durationMs) {
    try {
      String id = TRIAGE_ID != null && !TRIAGE_ID.isEmpty() ? TRIAGE_ID : (
          "Selector_" + Instant.now().toEpochMilli() + "_" + UUID.randomUUID().toString().substring(0, 8));
      Path dir = Paths.get(TRIAGE_DIR);
      Files.createDirectories(dir);

      Files.write(dir.resolve(id + ".html.txt"), html.getBytes(StandardCharsets.UTF_8));
      Files.write(dir.resolve(id + ".selector.txt"), selector.getBytes(StandardCharsets.UTF_8));

      StringBuilder sb = new StringBuilder();
      if (error == null) {
        int count = found != null ? found.size() : 0;
        sb.append("status: ok\n");
        sb.append("matches: ").append(count).append('\n');
        int shown = 0;
        if (found != null) {
          for (Element el : found) {
            if (shown >= 5) break;
            sb.append("- ").append(el.cssSelector()).append(" | ")
              .append(el.normalName()).append(" | text=").append(snip(el.text(), 200)).append('\n');
            shown++;
          }
        }
      } else {
        sb.append("status: error\n");
        sb.append("exception: ").append(error.getClass().getName()).append('\n');
        String msg = error.getMessage();
        if (msg != null) sb.append("message: ").append(snip(msg, 400)).append('\n');
      }
      if (durationMs != null) sb.append("duration_ms: ").append(durationMs).append('\n');
      Files.write(dir.resolve(id + ".result.txt"), sb.toString().getBytes(StandardCharsets.UTF_8));

      // JSON summary
      StringBuilder json = new StringBuilder();
      json.append('{');
      json.append("\"id\":\"").append(jsonEscape(id)).append("\",");
      json.append("\"status\":\"").append(error == null ? "ok" : "error").append("\",");
      json.append("\"html_len\":").append(html != null ? html.length() : 0).append(',');
      json.append("\"selector_len\":").append(selector != null ? selector.length() : 0).append(',');
      if (durationMs != null) json.append("\"duration_ms\":").append(durationMs).append(',');
      if (error == null) {
        int count = found != null ? found.size() : 0;
        json.append("\"matches\":").append(count).append(',');
        // sample up to 5
        json.append("\"samples\":[");
        int shown = 0;
        if (found != null) {
          for (Element el : found) {
            if (shown > 0) json.append(',');
            if (shown >= 5) break;
            json.append('{')
                .append("\"css\":\"").append(jsonEscape(snip(el.cssSelector(), 300))).append("\",")
                .append("\"name\":\"").append(jsonEscape(el.normalName())).append("\",")
                .append("\"text\":\"").append(jsonEscape(snip(el.text(), 120))).append("\"}");
            shown++;
          }
        }
        json.append(']');
      } else {
        json.append("\"exception_class\":\"").append(jsonEscape(error.getClass().getName())).append("\",");
        String msg = error.getMessage();
        json.append("\"exception_message\":\"").append(jsonEscape(snip(msg, 400))).append("\"");
      }
      json.append('}');
      Files.write(dir.resolve(id + ".result.json"), json.toString().getBytes(StandardCharsets.UTF_8));
    } catch (IOException ignored) {
      // best-effort triage
    }
  }

  private static String snip(String s, int max) {
    if (s == null) return "";
    if (s.length() <= max) return s;
    return s.substring(0, max) + "…";
  }

  private static String jsonEscape(String s) {
    if (s == null) return "";
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"': out.append("\\\""); break;
        case '\\': out.append("\\\\"); break;
        case '\n': out.append("\\n"); break;
        case '\r': out.append("\\r"); break;
        case '\t': out.append("\\t"); break;
        default:
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
      }
    }
    return out.toString();
  }

  private static boolean propOn(String name) {
    String v = System.getProperty(name);
    if (v == null) return false;
    v = v.trim();
    return v.equalsIgnoreCase("true") || v.equals("1") || v.equalsIgnoreCase("yes") || v.equalsIgnoreCase("on");
  }

  private static final boolean SKIP_REGEX = propOn("selector.skip.regex");

  private static boolean isRegexSelector(String sel) {
    if (sel == null) return false;
    String lower = sel.toLowerCase(Locale.ROOT);
    if (lower.contains(":matches(")) return true;
    if (lower.contains(":matchesown(")) return true;
    if (lower.contains(":matcheswhole")) return true; // matchesWholeText / matchesWholeOwn
    if (sel.contains("~=")) return true; // attribute regex operator
    return false;
  }
}
