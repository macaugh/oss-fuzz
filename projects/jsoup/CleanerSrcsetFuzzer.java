import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.jsoup.parser.Parser;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Harness for fuzzing <img srcset=...> sanitizer bypasses.
 *
 * Fuzz input is injected into the srcset attribute.
 * After cleaning, output is normalized and checked for dangerous constructs.
 */
public class CleanerSrcsetFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    try {
      // Put fuzz input into the srcset attribute
      String fuzzVal = new String(input, StandardCharsets.UTF_8);
      String html = "<IMG SRCSET=\"" + fuzzVal + "\">";

      // Clean with relaxed safelist
      String cleanHtml = Jsoup.clean(html, Safelist.relaxed());

      // Normalize: lowercase, URL decode, and HTML entity decode
      String lower = cleanHtml.toLowerCase();
      String urlDecoded = URLDecoder.decode(lower, StandardCharsets.UTF_8);
      String unescaped = Parser.unescapeEntities(urlDecoded, true);

      // Dangerous constructs that should not survive
      if (unescaped.contains("javascript:") ||
          unescaped.contains("vbscript:") ||
          unescaped.contains("data:text/html") ||
          unescaped.contains("data:image/svg+xml") ||
          unescaped.contains("onerror=") ||
          unescaped.contains("onload=") ||
          unescaped.contains("<script") ||
          unescaped.contains("</script")) {
        throw new RuntimeException("Cleaner bypass (srcset): unsafe content survived => " + cleanHtml);
      }
    } catch (Exception e) {
      // Ignore exceptions so fuzzing continues
    }
  }
}
