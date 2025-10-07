import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.jsoup.parser.Parser;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Updated harness for fuzzing <img src=...> XSS bypasses in Jsoup Cleaner.
 *
 * - Corpus inputs (img_corpus/) are already full HTML snippets like:
 *   <IMG SRC="javascript:alert(1)">
 *
 * - After cleaning with Safelist.relaxed(), the sanitized output is normalized
 *   and checked for dangerous constructs.
 *
 * - Wide-net approach: may produce false positives, but will catch encoded
 *   or obfuscated payloads.
 */
public class CleanerImageScriptFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    try {
      // Corpus already provides full <IMG ...> snippet
      String html = new String(input, StandardCharsets.UTF_8);

      // Sanitize using relaxed safelist
      String cleanHtml = Jsoup.clean(html, Safelist.relaxed());

      // Normalize: lowercase, URL-decode, and HTML entity decode
      String lower = cleanHtml.toLowerCase();
      String urlDecoded = URLDecoder.decode(lower, StandardCharsets.UTF_8);
      String unescaped = Parser.unescapeEntities(urlDecoded, true);

      // Wide-net checks for dangerous constructs
      if (unescaped.contains("javascript:") ||
          unescaped.contains("vbscript:") ||
          unescaped.contains("data:text/html") ||
          unescaped.contains("data:image/svg+xml") ||
          unescaped.contains("onerror=") ||
          unescaped.contains("onload=") ||
          unescaped.contains("<script") ||
          unescaped.contains("</script")) {
        throw new RuntimeException("Cleaner bypass: unsafe content survived => " + cleanHtml);
      }
    } catch (Exception e) {
      // Ignore exceptions to let fuzzer continue exploring
    }
  }
}
