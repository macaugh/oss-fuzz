import org.jsoup.Jsoup;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.jsoup.safety.Safelist;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.stream.Stream;

/**
 * Non-crashing wide-net harness for preserveRelativeLinks(true).
 *
 * - Does NOT throw on findings. Instead: saveFindingAndContinue(reason, rawHtml, cleanedHtml, domDump)
 * - Detects high-confidence leads:
 *     * cleaned DOM contains <script>
 *     * any on* attribute remains
 *     * href/src starting with javascript: or vbscript:
 *     * data: URIs that look like executable HTML/SVG
 * - Saves findings to ./findings with a short hashed name and a small index.
 * - Swallows parser exceptions (but saves deduped raw + stack in ./artifacts/parser_crash_*).
 */
public class CleanerWideNetRelativeLinksFuzzerNoCrash {
  private static final Path FINDINGS_DIR = Paths.get("./findings");
  private static final Path ARTIFACTS_DIR = Paths.get("./artifacts");
  private static final int MAX_PARSER_SAVE = 100; // cap parser crash raws kept

  public static void fuzzerTestOneInput(byte[] input) {
    String raw = new String(input, StandardCharsets.UTF_8);
    String trimmed = raw.trim();
    String html = trimmed.startsWith("<") ? raw : ("<a href=\"" + raw + "\">x</a>");

    String cleaned;
    try {
      cleaned = Jsoup.clean(html, "https://example.com/", Safelist.basic().preserveRelativeLinks(true));
    } catch (Exception e) {
      // parser crash or other exception: save deduped parser crash info and continue
      saveParserCrash(html, e);
      return;
    }

    Document doc;
    try {
      doc = Jsoup.parse(cleaned, "https://example.com/");
    } catch (Exception e) {
      saveParserCrash(cleaned, e);
      return;
    }

    // Build a small DOM dump string for saving/inspection
    StringBuilder domDumpBuilder = new StringBuilder();
    for (Element el : doc.getAllElements()) {
      domDumpBuilder.append("TAG:").append(el.tagName());
      if (el.attributes().size() > 0) {
        domDumpBuilder.append(" ATTRS: ");
        for (Attribute a : el.attributes()) {
          domDumpBuilder.append(a.getKey()).append("=\"").append(a.getValue()).append("\" ");
        }
      }
      domDumpBuilder.append(System.lineSeparator());
    }
    String domDump = domDumpBuilder.toString();

    // High-confidence checks (if any match -> save finding and continue)
    // 1) script elements surviving
    if (doc.select("script").size() > 0) {
      saveFindingAndContinue("script_element_survived", html, cleaned, domDump);
      return;
    }

    // 2) event handler attributes surviving
    for (Element el : doc.getAllElements()) {
      for (Attribute attr : el.attributes()) {
        String k = attr.getKey().toLowerCase();
        if (k.startsWith("on") && attr.getValue() != null && !attr.getValue().trim().isEmpty()) {
          saveFindingAndContinue("event_handler_survived:" + k, html, cleaned, domDump);
          return;
        }
      }
    }

    // 3) href/src scheme checks
    for (Element el : doc.getAllElements()) {
      for (Attribute attr : el.attributes()) {
        String key = attr.getKey().toLowerCase();
        if (!("href".equals(key) || "src".equals(key) || key.endsWith("src") || key.endsWith("href"))) {
          continue;
        }
        String rawAttr = attr.getValue();
        if (rawAttr == null) continue;
        // unescape entities that might hide a scheme token
        String unescaped = Parser.unescapeEntities(rawAttr, true).trim().toLowerCase();

        // direct schemes
        if (unescaped.startsWith("javascript:") || unescaped.startsWith("vbscript:")) {
          saveFindingAndContinue("scheme_js_in_" + key, html, cleaned, domDump);
          return;
        }
        // data URIs that might contain HTML or SVG
        if (unescaped.startsWith("data:") && dataUriContainsExecutable(unescaped)) {
          saveFindingAndContinue("data_uri_executable_in_" + key, html, cleaned, domDump);
          return;
        }
      }
    }

    // no high-confidence finding; quiet continue
  }

  // Save a finding bundle into FINDINGS_DIR: raw, cleaned, dom and append an index line.
  private static void saveFindingAndContinue(String reason, String rawHtml, String cleanedHtml, String domDump) {
    try {
      Files.createDirectories(FINDINGS_DIR);
      String shortHash = shortHash(rawHtml);
      String ts = Instant.now().toString().replace(':', '-');
      String base = String.format("%s_%s", ts, shortHash);
      Path rawPath = FINDINGS_DIR.resolve(base + ".raw");
      Path cleanPath = FINDINGS_DIR.resolve(base + ".clean.txt");
      Path domPath = FINDINGS_DIR.resolve(base + ".dom.txt");
      Path metaPath = FINDINGS_DIR.resolve("index.txt");

      // write files
      Files.write(rawPath, rawHtml.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);
      Files.write(cleanPath, cleanedHtml.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);
      Files.write(domPath, domDump.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);

      // index line
      String idxLine = Instant.now().toString() + " | " + shortHash + " | " + reason + " | " + base + System.lineSeparator();
      Files.write(metaPath, idxLine.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE, StandardOpenOption.APPEND);

      System.out.println("[FINDING SAVED] " + reason + " -> " + base);
    } catch (Exception e) {
      // fail-safe: print to stdout but don't throw
      System.err.println("[FINDING SAVE ERROR] " + e.getMessage());
    }
  }

  // Save parser crash raw + stacktrace to ./artifacts with dedupe by short hash.
  private static void saveParserCrash(String html, Throwable ex) {
    try {
      Files.createDirectories(ARTIFACTS_DIR);

      String h = shortHash(html);
      long ts = System.currentTimeMillis();
      String base = "parser_crash_" + ts + "_" + h;
      Path rawPath = ARTIFACTS_DIR.resolve(base + ".raw");
      Path stackPath = ARTIFACTS_DIR.resolve(base + ".stack.txt");

      // dedupe: skip if a raw with same short-hash exists
      boolean already = false;
      try (Stream<Path> s = Files.list(ARTIFACTS_DIR)) {
        already = s.anyMatch(p -> p.getFileName().toString().contains("_" + h + ".raw"));
      } catch (Exception ignore) { already = false; }

      if (!already) {
        Files.write(rawPath, html.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);
      }

      // write stack
      StringBuilder trace = new StringBuilder();
      trace.append(ex.toString()).append(System.lineSeparator());
      for (StackTraceElement ste : ex.getStackTrace()) {
        trace.append("    at ").append(ste.toString()).append(System.lineSeparator());
      }
      Files.write(stackPath, trace.toString().getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);

      // cap number of saved raw parser crash files
      try (Stream<Path> stream = Files.list(ARTIFACTS_DIR)) {
        Path[] raws = stream.filter(p -> p.getFileName().toString().endsWith(".raw")).toArray(Path[]::new);
        if (raws.length > MAX_PARSER_SAVE) {
          // sort by creation/mtime ascending and delete oldest
          java.util.Arrays.sort(raws, Comparator.comparingLong(p -> {
            try {
              return Files.getLastModifiedTime(p).toMillis();
            } catch (Exception e) { return Long.MAX_VALUE; }
          }));
          int toDelete = raws.length - MAX_PARSER_SAVE;
          for (int i = 0; i < toDelete; i++) {
            try {
              Files.deleteIfExists(raws[i]);
              String name = raws[i].getFileName().toString();
              Files.deleteIfExists(ARTIFACTS_DIR.resolve(name + ".stack.txt"));
            } catch (Exception ignore) { }
          }
        }
      }
      System.out.println("[PARSER CRASH SAVED] " + base);
    } catch (Exception e) {
      // swallow
      System.err.println("[PARSER SAVE ERROR] " + e.getMessage());
    }
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
          try { decoded = new String(Base64.getDecoder().decode(payload), StandardCharsets.UTF_8); }
          catch (Exception ex) { decoded = ""; }
        } else {
          try { decoded = java.net.URLDecoder.decode(payload, StandardCharsets.UTF_8.name()); }
          catch (Exception ex) { decoded = payload; }
        }
        String low = decoded.toLowerCase();
        return low.contains("<script") || low.contains("onload=") || low.contains("onerror=") || low.contains("svg");
      }
    } catch (Exception e) { }
    return false;
  }

  private static String shortHash(String s) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < 8 && i < d.length; i++) sb.append(String.format("%02x", d[i]));
      return sb.toString();
    } catch (Exception e) {
      return Integer.toHexString(s.hashCode());
    }
  }
}
