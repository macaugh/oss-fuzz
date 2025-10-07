package harnesses;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.jsoup.select.Selector;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.UUID;

public class RunSelectorRepro {
  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      System.err.println("Usage: java -cp .:jsoup.jar harnesses.RunSelectorRepro <html_file> <selector_file> [ID]");
      System.exit(2);
    }
    String html = Files.readString(Paths.get(args[0]), StandardCharsets.UTF_8);
    String selector = Files.readString(Paths.get(args[1]), StandardCharsets.UTF_8).trim();
    String id = args.length >= 3 ? args[2] : ("Manual_" + Instant.now().toEpochMilli() + "_" + UUID.randomUUID().toString().substring(0,8));
    String outDir = System.getProperty("selector.triage.dir", "findings/selector");

    long t0 = System.nanoTime();
    try {
      Document doc = Jsoup.parse(html);
      Elements found = doc.select(selector);
      long t1 = System.nanoTime();
      emit(outDir, id, html, selector, found, null, (t1 - t0) / 1_000_000L);

      System.out.printf("[ReproSelector] OK: matches=%d, duration_ms=%d%n", found.size(), (t1 - t0)/1_000_000L);
      int show = Math.min(5, found.size());
      for (int i = 0; i < show; i++) {
        Element el = found.get(i);
        System.out.println("  - " + el.cssSelector() + " | " + el.normalName() + " | text=" + snip(el.text(), 120));
      }
    } catch (Selector.SelectorParseException | IllegalArgumentException e) {
      emit(outDir, id, html, selector, null, e, null);
      System.out.println("[ReproSelector] Parse error: " + e.getMessage());
    } catch (Throwable t) {
      emit(outDir, id, html, selector, null, t, null);
      System.out.println("[ReproSelector] Exception: " + t.getClass().getName() + ": " + t.getMessage());
      t.printStackTrace(System.out);
    }
  }

  private static void emit(String dir, String id, String html, String selector, Elements found, Throwable error, Long durationMs) throws IOException {
    Files.createDirectories(Path.of(dir));
    Files.write(Path.of(dir, id + ".html.txt"), html.getBytes(StandardCharsets.UTF_8));
    Files.write(Path.of(dir, id + ".selector.txt"), selector.getBytes(StandardCharsets.UTF_8));
    StringBuilder sb = new StringBuilder();
    if (error == null) {
      int count = found != null ? found.size() : 0;
      sb.append("status: ok\n");
      sb.append("matches: ").append(count).append('\n');
      int shown = 0;
      if (found != null) {
        for (Element el : found) {
          if (shown >= 5) break;
          sb.append("- ").append(el.cssSelector()).append(" | ")
            .append(el.normalName()).append(" | text=").append(snip(el.text(), 200)).append('\n');
          shown++;
        }
      }
    } else {
      sb.append("status: error\n");
      sb.append("exception: ").append(error.getClass().getName()).append('\n');
      String msg = error.getMessage();
      if (msg != null) sb.append("message: ").append(snip(msg, 400)).append('\n');
    }
    if (durationMs != null) sb.append("duration_ms: ").append(durationMs).append('\n');
    Files.write(Path.of(dir, id + ".result.txt"), sb.toString().getBytes(StandardCharsets.UTF_8));
  }

  private static String snip(String s, int max) {
    if (s == null) return "";
    if (s.length() <= max) return s;
    return s.substring(0, max) + "…";
  }
}

