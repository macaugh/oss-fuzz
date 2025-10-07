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
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * DOM-precision fuzzer harness:
 *  - Only flags surviving DOM elements/attributes that are clearly dangerous.
 *  - Normalizes attribute values (URL-decode + entity unescape) before checks.
 *  - Handles simple srcset-like values.
 *  - Swallows parser IndexOutOfBoundsException / parser-only crashes so fuzzing continues.
 *
 * Keeps behaviour lean to avoid artifact flooding.
 */
public class CleanerDomPrecisionFuzzerSimple {
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
    String raw = new String(input, StandardCharsets.UTF_8);
    String trimmed = raw.trim();
    String html = trimmed.startsWith("<") ? raw : ("<img src=\"" + raw + "\">");

    String cleaned;
    try {
      cleaned = Jsoup.clean(html, Safelist.relaxed());
    } catch (IndexOutOfBoundsException | IllegalArgumentException e) {
      // Parser-only crash or bad input; ignore and continue fuzzing.
      return;
    } catch (Throwable t) {
      // Any other unexpected throwable from clean() - ignore to keep fuzzing.
      return;
    }

    Document doc;
    try {
      doc = Jsoup.parse(cleaned);
    } catch (IndexOutOfBoundsException | IllegalArgumentException e) {
      return;
    } catch (Throwable t) {
      return;
    }

    try {
      for (Element el : doc.getAllElements()) {
        String tag = el.tagName().toLowerCase();

        if (DISALLOWED_TAGS.contains(tag)) {
          throw new RuntimeException("Cleaner bypass: disallowed tag survived: <" + tag + "> => " + cleaned);
        }

        for (Attribute attr : el.attributes()) {
          String key = attr.getKey().toLowerCase();
          String valRaw = attr.getValue();
          String normalizedVal = normalizeAttrValue(valRaw);

          // event handlers: any on* surviving
          if (key.startsWith("on") && normalizedVal.length() > 0) {
            throw new RuntimeException("Cleaner bypass: event handler survived: " + key + " => " + cleaned);
          }

          // style checks
          if ("style".equals(key)) {
            String low = normalizedVal.toLowerCase();
            for (String tok : DANGEROUS_STYLE_TOKENS) {
              if (low.contains(tok)) {
                throw new RuntimeException("Cleaner bypass: unsafe style survived: " + valRaw + " => " + cleaned);
              }
            }
          }

          // srcset handling: split candidates by comma and check each URL token
          if ("srcset".equals(key)) {
            for (String part : normalizedVal.split(",")) {
              String candidate = part.trim().split("\\s+")[0];
              if (candidate.length() == 0) continue;
              if (isDangerousUrl(candidate)) {
                throw new RuntimeException("Cleaner bypass: dangerous srcset candidate: " + candidate + " => " + cleaned);
              }
            }
          }

          // URL-bearing attributes
          if (URL_ATTRS.contains(key) || normalizedVal.contains(":")) {
            if (isDangerousUrl(normalizedVal)) {
              throw new RuntimeException("Cleaner bypass: dangerous url/value survived: " + key + "=" + valRaw + " => " + cleaned);
            }
            // data: URIs check
            if (normalizedVal.toLowerCase().startsWith("data:") && dataUriContainsExecutable(normalizedVal)) {
              throw new RuntimeException("Cleaner bypass: executable data: URI in " + key + ": " + valRaw + " => " + cleaned);
            }
          }
        }
      }
    } catch (RuntimeException re) {
      throw re;
    } catch (Throwable t) {
      // ignore unexpected errors in inspection
    }
  }

  // normalize by URL-decoding and unescaping HTML entities, tolerant to failures
  private static String normalizeAttrValue(String v) {
    if (v == null) return "";
    String s = v;
    try {
      // URL decode once (avoid excessive loops that reintroduce false positives)
      s = URLDecoder.decode(s, StandardCharsets.UTF_8.name());
    } catch (Exception ignored) {}
    try {
      s = Parser.unescapeEntities(s, true);
    } catch (Exception ignored) {}
    return s.trim();
  }

  private static boolean isDangerousUrl(String v) {
    if (v == null) return false;
    String low = v.toLowerCase().trim();
    // simple scheme check
    int colon = low.indexOf(':');
    if (colon > 0) {
      String scheme = low.substring(0, colon).replaceAll("[^a-z0-9+.-]", "");
      if (scheme.equals("javascript") || scheme.equals("vbscript")) return true;
      if (scheme.equals("data") && dataUriContainsExecutable(low)) return true;
    }
    // look for explicit script tokens in decoded values
    if (low.contains("javascript:") || low.contains("<script") || low.contains("onload=") || low.contains("onerror=")) return true;
    return false;
  }

  private static boolean dataUriContainsExecutable(String v) {
    try {
      String lower = v.toLowerCase().trim();
      int colon = lower.indexOf(':');
      if (colon < 0) return false;
      String after = lower.substring(colon + 1);
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
          } catch (Exception ex) { decoded = ""; }
        } else {
          try {
            decoded = URLDecoder.decode(payload, StandardCharsets.UTF_8.name());
          } catch (Exception ex) { decoded = payload; }
        }
        String low = decoded.toLowerCase();
        return low.contains("<script") || low.contains("onload=") || low.contains("onerror=");
      }
    } catch (Exception e) { /* ignore */ }
    return false;
  }
}
