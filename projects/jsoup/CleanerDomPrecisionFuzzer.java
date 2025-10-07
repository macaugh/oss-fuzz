import org.jsoup.Jsoup;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.safety.Safelist;
import org.jsoup.parser.Parser;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.Base64;

/**
 * DOM-precision fuzz harness for Jsoup Cleaner.
 *
 * - Accepts either a full HTML snippet (seed file starts with "<") or a payload
 *   that will be wrapped into a sensible tag (img src="...").
 * - Calls Jsoup.clean(..., Safelist.relaxed()) and parses the cleaned HTML.
 * - Inspects the parsed Document: throws ONLY if actual elements/attributes survive
 *   that are dangerous (script tag, on* attributes, javascript: schemes, data: with executable payloads,
 *   style with expression/url(javascript:), etc).
 *
 * This reduces false positives compared to text-only heuristics.
 */
public class CleanerDomPrecisionFuzzer {
  private static final Set<String> URL_ATTRS = new HashSet<>(Arrays.asList(
      "href","src","xlink:href","formaction","action","poster","data","srcset","cite"
  ));

  private static final Set<String> DISALLOWED_TAGS = new HashSet<>(Arrays.asList(
      "script","iframe","embed","object","base"
  ));

  private static final Set<String> DANGEROUS_STYLE_TOKENS = new HashSet<>(Arrays.asList(
      "expression(", "url(javascript:", "@import"
  ));

  public static void fuzzerTestOneInput(byte[] input) {
    try {
      // Build HTML: if input looks like full HTML snippet (starts with '<'), use as-is.
      // Otherwise, wrap as an <img src="..."> (common target).
      String raw = new String(input, StandardCharsets.UTF_8);
      String trimmed = raw.trim();
      String html;
      if (trimmed.startsWith("<")) {
        html = raw;
      } else {
        html = "<img src=\"" + raw + "\">";
      }

      // Clean with the same safelist we're testing (relaxed)
      String cleaned = Jsoup.clean(html, Safelist.relaxed());

      // Parse the cleaned HTML to inspect DOM nodes (this is the "precision" step)
      Document doc = Jsoup.parse(cleaned);

      // Iterate elements and inspect
      for (Element el : doc.getAllElements()) {
        String tag = el.tagName().toLowerCase();

        // 1) disallowed tags surviving (script, iframe, embed, object, base)
        if (DISALLOWED_TAGS.contains(tag)) {
          throw new RuntimeException("Cleaner bypass: disallowed tag survived: <" + tag + "> => " + cleaned);
        }

        // 2) attributes checks
        for (Attribute attr : el.attributes()) {
          String key = attr.getKey().toLowerCase();
          String valRaw = attr.getValue();
          String val = valRaw == null ? "" : valRaw.trim();

          // event handlers: on*
          if (key.startsWith("on") && !val.isEmpty()) {
            throw new RuntimeException("Cleaner bypass: event handler survived: " + key + "=\"" + val + "\" => " + cleaned);
          }

          // style attribute checks (CSS-based vectors)
          if ("style".equals(key)) {
            String low = val.toLowerCase();
            for (String tok : DANGEROUS_STYLE_TOKENS) {
              if (low.contains(tok)) {
                throw new RuntimeException("Cleaner bypass: unsafe style survived: " + valRaw + " => " + cleaned);
              }
            }
          }

          // URL-bearing attributes (canonicalize scheme if possible)
          if (URL_ATTRS.contains(key) || looksLikeUrlLike(val)) {
            String scheme = extractScheme(val);
            if (scheme != null) {
              String s = scheme.toLowerCase();
              if (s.equals("javascript") || s.equals("vbscript")) {
                throw new RuntimeException("Cleaner bypass: dangerous scheme in " + key + ": " + valRaw + " => " + cleaned);
              }
              if (s.equals("data")) {
                if (dataUriContainsExecutable(val)) {
                  throw new RuntimeException("Cleaner bypass: executable data: URI in " + key + ": " + valRaw + " => " + cleaned);
                }
              }
            } else {
              // No clear scheme; but check for explicit tokens that indicate javascript-like payloads
              String low = Parser.unescapeEntities(val.toLowerCase(), true);
              if (low.contains("javascript:") || low.contains("vbscript:")) {
                throw new RuntimeException("Cleaner bypass: javascript token in attr value: " + valRaw + " => " + cleaned);
              }
            }
          }
        }
      }

      // If we get here, nothing unsafe survived at DOM level. Do not throw.
    } catch (RuntimeException re) {
      // Rethrow deliberate security findings so Jazzer records them.
      throw re;
    } catch (Exception e) {
      // Ignore parsing/decoding runtime exceptions to keep fuzzing running.
    }
  }

  private static boolean looksLikeUrlLike(String v) {
    if (v == null) return false;
    return v.contains(":") || v.contains("%") || v.startsWith("data") || v.startsWith("javascript");
  }

  // Extract a rough scheme from a value (returns null if none).
  // Does not throw; tolerant of garbage.
  private static String extractScheme(String val) {
    if (val == null) return null;
    String t = val.trim();
    int colon = t.indexOf(':');
    if (colon <= 0) return null;
    String scheme = t.substring(0, colon);
    // strip non-scheme characters conservatively
    scheme = scheme.replaceAll("[^A-Za-z0-9+.-]", "");
    return scheme.isEmpty() ? null : scheme;
  }

  // Inspect data: URIs and check for embedded executable content (text/html, image/svg+xml, etc).
  private static boolean dataUriContainsExecutable(String v) {
    try {
      String lower = v.toLowerCase().trim();
      int colon = lower.indexOf(':');
      if (colon < 0) return false;
      String after = lower.substring(colon + 1); // after "data:"
      int comma = after.indexOf(',');
      if (comma < 0) return false;
      String meta = after.substring(0, comma);
      String payload = after.substring(comma + 1);

      boolean isBase64 = meta.contains(";base64");
      String mediatype = meta.split(";")[0];
      if (mediatype == null || mediatype.isEmpty()) mediatype = "text/plain";

      if (mediatype.contains("html") || mediatype.contains("text") || mediatype.contains("svg")) {
        String decoded;
        if (isBase64) {
          try {
            byte[] dec = Base64.getDecoder().decode(payload);
            decoded = new String(dec, StandardCharsets.UTF_8);
          } catch (Exception ex) {
            decoded = "";
          }
        } else {
          decoded = URLDecoder.decode(payload, StandardCharsets.UTF_8);
        }
        String low = decoded.toLowerCase();
        if (low.contains("<script") || low.contains("onload=") || low.contains("onerror=") || low.contains("svg")) {
          return true;
        }
      }
    } catch (Exception e) { /* ignore and assume not executable */ }
    return false;
  }
}
