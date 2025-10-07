package fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.safety.Safelist;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Property under test:
 *  For any input HTML, Jsoup.clean(input, Safelist.relaxed()) must NOT produce
 *  sanitized output that still contains:
 *    - <script> (or variants) or other explicitly disallowed elements,
 *    - event-handler attributes (on*),
 *    - dangerous URL schemes in URL-bearing attributes (javascript:, vbscript:, data:text/html, file:).
 *
 * If any of the above appear in the CLEANED output, we raise a security finding.
 */
public class CleanerBypassFuzzer {
  // Attributes that can carry URLs (keep list tight to reduce noise)
  private static final Set<String> URL_ATTRS = new HashSet<>(Arrays.asList(
      "href", "src", "xlink:href", "formaction", "action", "poster"
  ));

  // Elements that should never survive relaxed cleaning if they enable script execution
  // (svg/math are conservative: if they ever survive, we want to look.)
  private static final Set<String> DISALLOWED_TAGS = new HashSet<>(Arrays.asList(
      "script", "noscript", "iframe", "embed", "object", "base", "svg", "math"
  ));

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    // Generate some variability that *could* matter to the cleaner
    String baseUri = data.consumeBoolean() ? "" : data.consumeString(64);
    String input = data.consumeRemainingAsString();

    // Sanitize using relaxed rules (same family as your unit test)
    String clean = Jsoup.clean(input, baseUri, Safelist.relaxed());

    // Parse what the *sanitizer produced* and inspect that DOM, not the raw string
    Document doc = Jsoup.parse(clean);

    for (Element el : doc.getAllElements()) {
      String tag = el.tagName().toLowerCase(Locale.ROOT);

      // 1) Tag checks
      if (DISALLOWED_TAGS.contains(tag)) {
        throw new FuzzerSecurityIssueHigh("Cleaner bypass: disallowed tag survived: <" + tag + ">");
      }

      // 2) Attribute checks
      for (Attribute a : el.attributes()) {
        String key = a.getKey().toLowerCase(Locale.ROOT);
        String val = a.getValue().trim().toLowerCase(Locale.ROOT);

        // Event handlers (onclick, onerror, onload, …)
        if (key.startsWith("on")) {
          throw new FuzzerSecurityIssueHigh("Cleaner bypass: event handler attribute survived: " + key);
        }

        // Dangerous URL schemes on URL-bearing attributes
        if (URL_ATTRS.contains(key)) {
          if (val.startsWith("javascript:")
              || val.startsWith("vbscript:")
              || val.startsWith("data:text/html")
              || val.startsWith("file:")) {
            throw new FuzzerSecurityIssueHigh(
                "Cleaner bypass: dangerous URL scheme in " + key + " => " + val);
          }
        }

        // Inline CSS nasties (if style ever survives; relaxed normally strips it)
        if ("style".equals(key)) {
          if (val.contains("expression(") || val.contains("url(javascript:") || val.contains("@import")) {
            throw new FuzzerSecurityIssueHigh("Cleaner bypass: unsafe CSS in style attribute: " + val);
          }
        }
      }
    }
  }
}
