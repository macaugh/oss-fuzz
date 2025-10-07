import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.helper.W3CDom;
import org.jsoup.helper.DataUtil;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class Repro {
  public static void main(String[] args) throws Exception {
    byte[] bytes = Files.readAllBytes(Path.of(args[0]));
    String html = new String(bytes, StandardCharsets.UTF_8);

    try {
      // 1. Standard parse
      Document doc = Jsoup.parse(html);

      // 2. Fragment parse (this is likely where the crash comes from)
      Jsoup.parseBodyFragment(html);

      // 3. DataUtil.load (encoding path)
      DataUtil.load(new ByteArrayInputStream(bytes), "UTF-8", null);

      // 4. Base URI path
      try {
        String base = "http://example.com/";
        URL url = new URL(base + html.replaceAll("[^a-zA-Z0-9]", ""));
        Jsoup.parse(html, url.toString());
      } catch (Exception ignored) {}

      // 5. W3C DOM conversion
      W3CDom w3c = new W3CDom();
      w3c.fromJsoup(doc);

    } catch (IllegalArgumentException | IOException ignored) {
      // benign failures
    } catch (Throwable t) {
      t.printStackTrace();
    }
  }
}
