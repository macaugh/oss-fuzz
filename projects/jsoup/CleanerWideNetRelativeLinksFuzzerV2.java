// CleanerWideNetRelativeLinksFuzzerV2.java
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.jsoup.safety.Safelist;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;

/**
 * Wide-net harness targeted at preserveRelativeLinks(true).
 * - Flags only when href begins with javascript: or vbscript: (high-confidence).
 * - Ignores non-actionable occurrences where "javascript:" appears inside a fragment or path
 *   (e.g. "#/javascript:...", "/javascript:...") — these are logged to artifacts/ignored_leads.log
 *   for later manual review, but do NOT crash the fuzzer.
 *
 * - Writes ignored leads with basic dedupe to artifacts/ignored_leads.log
 */
public class CleanerWideNetRelativeLinksFuzzerV2 {
  private static final Path ARTIFACTS = Paths.get("./artifacts");
  private static final Path IGNORED_LOG = ARTIFACTS.resolve("ignored_leads.log");

  public static void fuzzerTestOneInput(byte[] input) {
    String raw = new String(input, StandardCharsets.UTF_8).trim();
    String html = raw.startsWith("<") ? raw : ("<a href=\"" + raw + "\">x</a>");

    String cleaned;
    try {
      // use preserveRelativeLinks(true) as requested
      cleaned = Jsoup.clean(html, "https://example.com/", Safelist.basic().preserveRelativeLinks(true));
    } catch (Throwable t) {
      // parser crash or other parse error — not our focus; ignore and continue fuzzing
      return;
    }

    Document doc = Jsoup.parse(cleaned);
    Element a = doc.selectFirst("a");
    if (a == null) return;

    // normalized attribute value (unescape entities) to avoid entity tricks evading checks
    String hrefRaw = a.attr("href");
    String hrefUnescaped = Parser.unescapeEntities(hrefRaw == null ? "" : hrefRaw, true);
    String href = hrefUnescaped.trim().toLowerCase();

    // High-confidence signal: href starting with javascript: or vbscript:
    if (href.startsWith("javascript:") || href.startsWith("vbscript:")) {
      throw new RuntimeException("Lead: JS-like scheme survived -> " + cleaned);
    }

    // Non-actionable cases we want to ignore:
    //  - Fragment-prefixed: "#/javascript:..." or "#!javascript:..." or simply "#" followed by path containing javascript:
    //  - Path-prefixed: "/javascript:..." (appears as a path or absolute-ish)
    // Treat these as non-exploitable; log them for later review.
    if (href.contains("javascript:") || href.contains("vbscript:")) {
      // If javascript appears but not at the beginning, decide if it is actionable.
      // If it is inside a fragment (starts with '#') or starts with '/' then ignore here.
      if (href.startsWith("#") || href.startsWith("/")) {
        logIgnoredLead(href, cleaned);
        return;
      }
      // If it contains encoded colon forms (e.g. &colon; or &#x3a;), Jsoup.clean may leave them;
      // if unescaped still contains 'javascript:' but not at 0 index, treat same as above.
      if (href.indexOf("javascript:") > 0) {
        // still likely non-actionable if not in scheme position; log and continue
        logIgnoredLead(href, cleaned);
        return;
      }
    }

    // Other suspicious tokens we may want to escalate (optional)
    // e.g. data: URIs with HTML/SVG payloads (possible executable)
    if (href.startsWith("data:")) {
      if (dataUriContainsExecutable(href)) {
        throw new RuntimeException("Lead: executable data: URI survived -> " + cleaned);
      }
    }

    // No finding
    return;
  }

  // Basic detection for data: URIs that might contain executable HTML/SVG/JS
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
          try { decoded = new String(java.util.Base64.getDecoder().decode(payload), StandardCharsets.UTF_8); }
          catch (Exception ex) { decoded = ""; }
        } else {
          try { decoded = java.net.URLDecoder.decode(payload, StandardCharsets.UTF_8.name()); }
          catch (Exception ex) { decoded = payload; }
        }
        String low = decoded.toLowerCase();
        return low.contains("<script") || low.contains("onload=") || low.contains("onerror=") || low.contains("svg");
      }
    } catch (Exception ignored) {}
    return false;
  }

  // Log ignored leads to artifacts/ignored_leads.log with simple dedupe (by short hash).
  private static void logIgnoredLead(String href, String cleaned) {
    try {
      Files.createDirectories(ARTIFACTS);
      String key = shortHash(href);
      String entry = Instant.now().toString() + " | " + key + " | " + href + " | " + cleaned + System.lineSeparator();

      // read file if exists to see if this hash already recorded
      boolean already = false;
      if (Files.exists(IGNORED_LOG)) {
        try {
          // cheap check: search for the short hash in file
          String content = new String(Files.readAllBytes(IGNORED_LOG), StandardCharsets.UTF_8);
          already = content.contains(key);
        } catch (IOException ignore) { already = false; }
      }

      if (!already) {
        // append atomically
        Files.write(IGNORED_LOG, entry.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
      }
    } catch (Exception e) {
      // best-effort only: don't crash fuzzer if logging fails
    }
  }

  private static String shortHash(String s) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < 6 && i < d.length; i++) sb.append(String.format("%02x", d[i]));
      return sb.toString();
    } catch (Exception e) {
      // fallback
      int h = s.hashCode();
      return Integer.toHexString(h);
    }
  }
}
