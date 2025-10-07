// CleanerGhsaGp7fRwcx9369Fuzzer.java
// Targeted regression fuzzer for jsoup Cleaner around URL scheme handling
// and preserveRelativeLinks behavior related to GHSA-gp7f-rwcx-9369.

import org.jsoup.Jsoup;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.jsoup.safety.Safelist;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class CleanerGhsaGp7fRwcx9369Fuzzer {
  private static final Set<String> URL_ATTRS = new HashSet<>(Arrays.asList(
      "href","src","xlink:href","formaction","action","poster","data","srcset","cite"
  ));

  public static void fuzzerTestOneInput(byte[] input) {
    String payload = new String(input, StandardCharsets.UTF_8);

    // Build a small suite of focused HTMLs exercising href/src and relative links
    String[] candidates = new String[] {
        wrapAnchor(payload),
        wrapImg(payload),
        wrapForm(payload),
        wrapSvgXlink(payload),
        // simple srcset case (common normalizer differences)
        "<img srcset=\"" + safeAttr(payload) + " 1x\">"
    };

    // Exercise both preserveRelativeLinks=false and true to stress scheme parsing/normalization
    Safelist base = Safelist.basic();
    Safelist withRel = Safelist.basic().preserveRelativeLinks(true);

    for (String html : candidates) {
      // Pass 1: default
      inspectClean(Jsoup.clean(html, "https://example.com/", base));
      // Pass 2: preserve relative
      inspectClean(Jsoup.clean(html, "https://example.com/", withRel));
    }
  }

  private static void inspectClean(String cleaned) {
    try {
      Document d = Jsoup.parse(cleaned);
      for (Element el : d.getAllElements()) {
        // Event handlers should never survive
        for (Attribute a : el.attributes()) {
          String key = a.getKey().toLowerCase();
          String valRaw = a.getValue();
          if (key.startsWith("on") && !isEmpty(valRaw)) {
            throw new RuntimeException("Cleaner bypass: event attr survived -> " + key + " => " + cleaned);
          }
        }

        // URL-bearing attributes: canonicalize and assert no executable schemes survive
        for (Attribute a : el.attributes()) {
          String key = a.getKey();
          if (!URL_ATTRS.contains(key.toLowerCase())) continue;
          String valRaw = a.getValue();
          if (valRaw == null || valRaw.isEmpty()) continue;

          // Special-case srcset: multiple URLs separated by commas; check each
          if (key.equalsIgnoreCase("srcset")) {
            String[] parts = valRaw.split(",");
            for (String part : parts) {
              String urlToken = part.trim().split("\\s+")[0];
              checkUrlLike(cleaned, a.getKey(), urlToken);
            }
          } else {
            checkUrlLike(cleaned, a.getKey(), valRaw);
          }
        }
      }
    } catch (RuntimeException re) {
      throw re; // finding
    } catch (Exception ignored) {
      // keep fuzzing
    }
  }

  private static void checkUrlLike(String cleaned, String attr, String rawVal) {
    String canon = canonicalizeForSchemeCheck(rawVal);
    if (canon.isEmpty()) return;

    // javascript:, vbscript:, and protocol-relative //javascript: forms
    if (startsWithScheme(canon, "javascript") || startsWithScheme(canon, "vbscript") || canon.startsWith("//javascript:")) {
      throw new RuntimeException("Cleaner bypass: dangerous scheme survived in " + attr + " => " + cleaned);
    }

    // data: URIs with executable payloads (html/svg with script or on*)
    if (canon.startsWith("data:")) {
      if (dataUriExecutable(canon)) {
        throw new RuntimeException("Cleaner bypass: executable data: URI in " + attr + " => " + cleaned);
      }
    }
  }

  private static boolean startsWithScheme(String s, String scheme) {
    return s.startsWith(scheme + ":");
  }

  private static boolean dataUriExecutable(String v) {
    try {
      int comma = v.indexOf(',');
      if (comma < 0) return false;
      String meta = v.substring(5, comma); // after "data:"
      String payload = v.substring(comma + 1);
      boolean b64 = meta.contains(";base64");
      String mediatype = meta.split(";")[0];
      // decode percent-encoding inside mediatype and lowercase for comparisons
      mediatype = urlDecodeLoose(mediatype).toLowerCase();
      if (mediatype == null || mediatype.isEmpty()) mediatype = "text/plain";

      if (mediatype.contains("html") || mediatype.contains("text") || mediatype.contains("svg") || mediatype.contains("xml")) {
        String dec;
        if (b64) {
          try { dec = new String(Base64.getDecoder().decode(payload), StandardCharsets.UTF_8); }
          catch (Exception ex) { dec = ""; }
        } else {
          dec = urlDecodeLoose(payload);
        }
        String n = normalize(dec);
        return n.contains("<script") || n.contains(" onload=") || n.contains(" onerror=") || n.contains("<svg");
      }
    } catch (Exception ignored) {}
    return false;
  }

  private static String normalize(String s) {
    if (s == null) return "";
    String cur = s;
    try {
      // remove common control chars, zero-widths, and bidi overrides that browsers ignore
      cur = stripControls(cur);
      cur = Parser.unescapeEntities(cur, true);
      cur = Normalizer.normalize(cur, Normalizer.Form.NFKC);
      cur = stripControls(cur);
      // collapse multiple spaces
      cur = cur.replaceAll("\\s+", " ");
      cur = cur.trim();
      cur = cur.toLowerCase();
    } catch (Exception ignored) {}
    return cur;
  }

  // Canonicalization for scheme checks approximating browser URL parser behavior
  private static String canonicalizeForSchemeCheck(String s) {
    if (s == null) return "";
    String cur = s;
    try {
      // unescape HTML entities then URL-decode a few rounds
      cur = Parser.unescapeEntities(cur, true);
      cur = urlDecodeLoose(cur);
      // normalize unicode width and compatibility forms
      cur = Normalizer.normalize(cur, Normalizer.Form.NFKC);
      // strip controls/zero-width/bidi markers browsers ignore in scheme parsing
      cur = stripControls(cur);
      // unify backslashes to forward slashes
      cur = cur.replace('\\', '/');
      // lowercase and trim
      cur = cur.toLowerCase().trim();
    } catch (Exception ignored) {}
    return cur;
  }

  private static String stripControls(String s) {
    StringBuilder sb = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      // drop ASCII C0 controls and DEL
      if ((c >= 0x00 && c <= 0x1F) || c == 0x7F) continue;
      // drop zero-widths and BOM
      if (c == 0x200B || c == 0x200C || c == 0x200D || c == 0x2060 || c == 0xFEFF) continue;
      // drop bidi control chars (LRE/RLE/RLO/PDF/LRM/RLM/LRI/RLI/FSI/PDI)
      if ((c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069) || c == 0x200E || c == 0x200F)
        continue;
      sb.append(c);
    }
    return sb.toString();
  }

  private static String wrapAnchor(String p) {
    return "<a href=\"" + safeAttr(p) + "\">x</a>";
  }
  private static String wrapImg(String p) {
    return "<img src=\"" + safeAttr(p) + "\">";
  }
  private static String wrapForm(String p) {
    return "<form action=\"" + safeAttr(p) + "\"><button>go</button></form>";
  }
  private static String wrapSvgXlink(String p) {
    return "<svg><a xlink:href=\"" + safeAttr(p) + "\">x</a></svg>";
  }

  private static String urlDecodeLoose(String s) {
    try {
      String cur = s;
      for (int i=0; i<4; i++) {
        String dec = java.net.URLDecoder.decode(cur, StandardCharsets.UTF_8.name());
        if (dec.equals(cur)) break;
        cur = dec;
      }
      return cur;
    } catch (Exception e) { return s; }
  }

  private static boolean isEmpty(String s) { return s == null || s.trim().isEmpty(); }
  private static String safeAttr(String s) { return s == null ? "" : s.replace('"','\''); }
}
