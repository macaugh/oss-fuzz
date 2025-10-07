import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
public class ShowClean {
  public static void main(String[] args) throws Exception {
    byte[] raw = Files.readAllBytes(Paths.get(args[0]));
    String s = new String(raw, StandardCharsets.UTF_8);
    System.out.println("RAW:");
    System.out.println(s);
    System.out.println("CLEAN:");
    System.out.println(Jsoup.clean(s, Safelist.relaxed()));
  }
}
