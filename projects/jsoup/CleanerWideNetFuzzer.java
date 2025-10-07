// CleanerWideNetFuzzer.java
import org.jsoup.Jsoup;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.safety.Safelist;
import org.jsoup.parser.Parser;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.Base64;

public class CleanerWideNetFuzzer {
  private static final Set<String> URL_ATTRS = new HashSet<>(Arrays.asList(
    "href","src","xlink:href","formaction","action","poster","data","srcset","cite"
  ));
  private static final Set<String> DANGEROUS_TAGS = new HashSet<>(Arrays.asList(
    "script","iframe","embed","object","base","svg","math","link"
  ));

  public static void fuzzerTestOneInput(byte[] input) {
    try {
      String raw = new String(input, StandardCharsets.UTF_8);
      String html;
      String t = raw.trim();
      // If corpus entry looks like an HTML snippet, use it raw; otherwise wrap it as generic payload into img/src
      if (t.startsWith("<")) {
        html = raw;
      } else {
        // try to guess where the payload should go; srcset/href cases may be provided by separate corpora
        html = "<img src=\"" + raw + "\" alt=\"x\">";
      }

      // Clean using Jsoup
      String clean = Jsoup.clean(html, Safelist.relaxed());

      // Produce several normalized strings for heuristic checks
      String normalized = normalizeWide(clean);

      // Quick wide text checks (catches many obfuscations after normalization)
      if (looksDangerousString(normalized)) {
        throw new RuntimeException("Cleaner bypass (wide-text): " + clean);
      }

      // DOM-based checks (higher precision): parse cleaned HTML and inspect tags/attrs
      Document d = Jsoup.parse(clean);
      for (Element el : d.getAllElements()) {
        String tag = el.tagName().toLowerCase();
        if (DANGEROUS_TAGS.contains(tag)) {
          throw new RuntimeException("Cleaner bypass (tag survived): <" + tag + "> => " + clean);
        }
        for (Attribute a : el.attributes()) {
          String key = a.getKey().toLowerCase();
          String valRaw = a.getValue();
          String val = normalizeWide(valRaw);

          // Event handlers: any on* attribute surviving
          if (key.startsWith("on")) {
            throw new RuntimeException("Cleaner bypass (event attr): " + key + " => " + clean);
          }

          // URL-bearing attributes: parse scheme canonicalized
          if (URL_ATTRS.contains(key) || looksLikeUrl(val)) {
            String scheme = extractScheme(val);
            if (scheme != null) {
              String s = scheme.toLowerCase();
              if (s.equals("javascript") || s.equals("vbscript")) {
                throw new RuntimeException("Cleaner bypass (unsafe scheme): " + scheme + " in " + key + " => " + clean);
              }
              if (s.equals("data")) {
                // parse data: URIs; if text/html or image/svg+xml, decode and inspect content for scripts/onload
                if (dataUriContainsExecutable(val)) {
                  throw new RuntimeException("Cleaner bypass (data: payload): " + valRaw + " => " + clean);
                }
              }
            } else {
              // no scheme: still check for javascript: like patterns in obf form
              if (val.contains("javascript:") || val.contains("vbscript:")) {
                throw new RuntimeException("Cleaner bypass (javascript token survived in attr): " + valRaw + " => " + clean);
              }
            }
          }

          // Style attribute heuristics
          if ("style".equals(key)) {
            String low = val.toLowerCase();
            if (low.contains("expression(") || low.contains("url(javascript:") || low.contains("@import")) {
              throw new RuntimeException("Cleaner bypass (style): " + valRaw + " => " + clean);
            }
          }
        }
      }

    } catch (RuntimeException re) {
      // rethrow security findings so Jazzer treats them as crashes
      throw re;
    } catch (Exception e) {
      // swallow parser/decoding exceptions and continue fuzzing
    }
  }

  // Wide normalization: lowercase, repeated percent-decode, HTML entity decode, Unicode NFKC, map fullwidth brackets to ASCII
  private static String normalizeWide(String s) {
    try {
      String cur = s;
      cur = cur.toLowerCase();
      // replace fullwidth angle brackets and fullwidth quotes to ASCII equivalents
      cur = cur.replace('\uFF1C', '<').replace('\uFF1E', '>').replace('\u02BA','"').replace('\u02B9','\'');
      // unicode normalization
      cur = Normalizer.normalize(cur, Normalizer.Form.NFKC);
      // iterative URL-decode up to 5 times (handles double encoding)
      for (int i=0;i<5;i++) {
        String dec = URLDecoder.decode(cur, StandardCharsets.UTF_8.name());
        if (dec.equals(cur)) break;
        cur = dec;
      }
      // HTML entity unescape using Jsoup parser helper
      cur = Parser.unescapeEntities(cur, true);
      // remove some control chars that filters may fold in
      cur = cur.replace("\u0000","").replace("\r"," ").replace("\n"," ").replace("\t"," ");
      return cur;
    } catch (Exception e) { return s.toLowerCase(); }
  }

  private static boolean looksDangerousString(String s) {
    return s.contains("javascript:") ||
           s.contains("vbscript:") ||
           s.contains("data:text/html") ||
           s.contains("data:image/svg+xml") ||
           s.contains("onerror=") ||
           s.contains("onload=") ||
           s.contains("expression(") ||
           s.contains("url(javascript:") ||
           s.contains("<script") ||
           s.contains("</script") ||
           s.contains("\uFF1Cscript"); // fullwidth heuristic
  }

  private static boolean looksLikeUrl(String v) {
    return v.contains(":") || v.contains("%") || v.contains("data") || v.contains("javascript");
  }

  private static String extractScheme(String v) {
    try {
      // If value like javascript:... or data:...
      String trimmed = v.trim();
      // handle cases where value is quoted or contains whitespace
      int idx = trimmed.indexOf(':');
      if (idx <= 0) return null;
      String scheme = trimmed.substring(0, idx);
      // canonicalize by removing enclosing quotes or garbage
      scheme = scheme.replaceAll("[^A-Za-z0-9+.-]",""); // rough
      return scheme;
    } catch (Exception e) { return null; }
  }

  private static boolean dataUriContainsExecutable(String v) {
    try {
      String lower = v.toLowerCase();
      int colon = lower.indexOf(':');
      if (colon < 0) return false;
      String after = lower.substring(colon + 1);
      // format: data:[<mediatype>][;base64],<data>
      int comma = after.indexOf(',');
      if (comma < 0) return false;
      String meta = after.substring(0, comma);
      String payload = after.substring(comma + 1);
      boolean isBase64 = meta.contains(";base64");
      String mediatype = meta.split(";")[0];
      if (mediatype == null || mediatype.isEmpty()) mediatype = "text/plain";
      if (mediatype.startsWith("text/html") || mediatype.startsWith("text/") || mediatype.contains("html") || mediatype.contains("svg")) {
        String decoded;
        if (isBase64) {
          try {
            byte[] dec = Base64.getDecoder().decode(payload);
            decoded = new String(dec, StandardCharsets.UTF_8);
          } catch (Exception ex) { decoded = ""; }
        } else {
          decoded = URLDecoder.decode(payload, StandardCharsets.UTF_8.name());
        }
        String n = normalizeWide(decoded);
        return n.contains("<script") || n.contains("onload=") || n.contains("onerror=") || n.contains("svg");
      }
    } catch (Exception e) {}
    return false;
  }
}
