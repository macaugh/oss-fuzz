package org.jsoup.fuzz;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.helper.W3CDom;
import org.jsoup.helper.DataUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class ParseFuzzer {
  // Jazzer will call this method and pass the raw fuzzing input
  public static void fuzzerTestOneInput(byte[] input) {
    try {
      String html = new String(input, StandardCharsets.UTF_8);

      // 1. Standard parse
      Document doc = Jsoup.parse(html);

      // 2. Fragment parse
      Jsoup.parseBodyFragment(html);

      // 3. Encoding-sensitive path
      DataUtil.load(new ByteArrayInputStream(input), "UTF-8", null);

      // 4. URL handling path
      try {
        String base = "http://example.com/";
        URL url = new URL(base + html.replaceAll("[^a-zA-Z0-9]", ""));
        Jsoup.parse(html, url.toString());
      } catch (Exception ignored) {}

      // 5. W3C conversion
      W3CDom w3c = new W3CDom();
      w3c.fromJsoup(doc);

    } catch (IllegalArgumentException | IOException ignored) {
      // expected on malformed input
    } catch (Throwable t) {
      throw t; // let Jazzer catch real crashes
    }
  }
}
