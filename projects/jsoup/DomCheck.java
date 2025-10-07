import org.jsoup.Jsoup; import org.jsoup.nodes.Document; import org.jsoup.nodes.Element;
import java.nio.file.Files; import java.nio.file.Paths; import java.nio.charset.StandardCharsets;
public class DomCheck {
  public static void main(String[] args) throws Exception {
    byte[] b = Files.readAllBytes(Paths.get(args[0]));
    String raw = new String(b, StandardCharsets.UTF_8);
    String clean = Jsoup.clean(raw, org.jsoup.safety.Safelist.relaxed());
    Document d = Jsoup.parse(clean);
    System.out.println("=== CLEAN DOM ELEMENTS ===");
    for (Element e : d.getAllElements()) {
      System.out.println("TAG:" + e.tagName());
      e.attributes().forEach(a -> System.out.println("  " + a.getKey() + " => " + a.getValue()));
    }
  }
}
