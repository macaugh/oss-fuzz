import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.helper.W3CDom;
import org.jsoup.helper.DataUtil;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class Repro2 {
  public static void main(String[] args) throws Exception {
    byte[] bytes = Files.readAllBytes(Path.of(args[0]));
    String html = new String(bytes, StandardCharsets.UTF_8);

    try {
      // 1. Standard parse
      Document doc = Jsoup.parse(html);

      // 2. Fragment parse (this is likely where the crash comes from)
      Jsoup.parseBodyFragment(html);

      System.out.println("No exception thrown");
    } catch (Throwable t) {
      t.printStackTrace();
      System.out.println("Exception class: " + t.getClass().getName());
    }
  }
}
