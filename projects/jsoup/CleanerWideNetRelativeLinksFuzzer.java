import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.safety.Safelist;

import java.nio.charset.StandardCharsets;

public class CleanerWideNetRelativeLinksFuzzer {

  public static void fuzzerTestOneInput(byte[] input) {
    String raw = new String(input, StandardCharsets.UTF_8).trim();

    // Always wrap into an anchor if not HTML
    String html = raw.startsWith("<") ? raw : "<a href=\"" + raw + "\">x</a>";

    String cleaned;
    try {
      cleaned = Jsoup.clean(html, "https://example.com/", Safelist.basic().preserveRelativeLinks(true));
    } catch (Throwable t) {
      // swallow parser crashes (not our focus here)
      return;
    }

    Document doc = Jsoup.parse(cleaned);
    Element a = doc.selectFirst("a");
    if (a == null) return;

    String href = a.attr("href").toLowerCase();

    // 🚨 Lead conditions (interesting cases)
    if (href.contains("javascript") || href.contains("vbscript")) {
      throw new RuntimeException("Lead: JS-like scheme survived → " + cleaned);
    }
    if (href.startsWith("//javascript")) {
      throw new RuntimeException("Lead: protocol-relative JS survived → " + cleaned);
    }
    if (href.contains("&colon;") || href.contains("&#x3a;")) {
      throw new RuntimeException("Lead: colon-entity survived → " + cleaned);
    }
    if (href.matches(".*\\p{C}.*")) { // control chars still present
      throw new RuntimeException("Lead: control chars in href → " + cleaned);
    }
  }
}
