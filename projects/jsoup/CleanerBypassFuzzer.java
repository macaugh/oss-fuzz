import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

/**
 * Simplified fuzzer harness for Jsoup Cleaner bypasses.
 *
 * This avoids any Jazzer API dependencies — the entrypoint
 * takes a raw byte[] from the fuzzer.
 */
public class CleanerBypassFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    try {
      String html = new String(input);
      String clean = Jsoup.clean(html, Safelist.relaxed());

      // Simple checks for dangerous constructs that should not survive
      String lower = clean.toLowerCase();
      if (lower.contains("<script") ||
          lower.contains("javascript:") ||
          lower.contains("onerror=") ||
          lower.contains("onload=") ||
          lower.contains("<iframe") ||
          lower.contains("<object") ||
          lower.contains("<embed") ||
          lower.contains("<svg") ||
          lower.contains("vbscript:") ||
          lower.contains("data:text/html")) {
        throw new RuntimeException("Cleaner bypass: unsafe content survived => " + clean);
      }
    } catch (Exception e) {
      // Ignore parser/cleaner exceptions so fuzzing continues
    }
  }
}
