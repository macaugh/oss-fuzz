import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

public class ShowCleanOnly {
  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      System.err.println("Usage: ShowCleanOnly <raw_input_file>");
      System.exit(2);
    }
    byte[] raw = Files.readAllBytes(Paths.get(args[0]));
    String s = new String(raw, StandardCharsets.UTF_8);
    // Use relaxed safelist; scheme handling is shared across safelists
    String cleaned = Jsoup.clean(s, Safelist.relaxed());
    System.out.print(cleaned);
  }
}

