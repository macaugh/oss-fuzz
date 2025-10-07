import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.safety.Cleaner;
import org.jsoup.safety.Safelist;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

/**
 * CleanLines
 * Reads a text file line-by-line, cleans each line with jsoup (Safelist.relaxed),
 * and writes the cleaned lines to findings/<basename>.clean.txt (or a custom name under findings/).
 */
public class CleanLines {
  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      System.err.println("Usage: java -cp .:jsoup.jar CleanLines <input.txt> [output_name.clean.txt]");
      System.exit(2);
    }

    String inPath = args[0];
    File inFile = new File(inPath);
    if (!inFile.isFile()) {
      System.err.println("Input not found or not a file: " + inFile.getPath());
      System.exit(3);
    }

    // Ensure findings/ exists
    File findingsDir = new File("findings");
    findingsDir.mkdirs();

    String outName;
    if (args.length >= 2) {
      outName = args[1];
    } else {
      String base = inFile.getName();
      outName = base + ".clean.txt";
    }
    File outFile = new File(findingsDir, outName);

    // Use relaxed safelist with preserveRelativeLinks enabled and permit additional tags
    Safelist safelist = Safelist.relaxed()
        .preserveRelativeLinks(true)
        .addTags("input", "button", "form", "video", "div", "dialog", "track", "select")
        // Allow specific URL-bearing attributes on relevant tags
        .addAttributes("blockquote", "cite")
        .addAttributes("q", "cite")
        .addAttributes("video", "poster");
    Cleaner cleaner = new Cleaner(safelist);
    // Provide a base URI so relative link preservation/normalization is deterministic
    final String baseUri = "https://example.com/";

    int lines = 0;
    int diffs = 0;

    try (
        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(inFile), StandardCharsets.UTF_8));
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))
    ) {
      String line;
      while ((line = br.readLine()) != null) {
        lines++;

        // Method 1: direct clean (with base URI)
        String cleanedA = Jsoup.clean(line, baseUri, safelist);

        // Method 2: explicit Cleaner on parsed fragment
        Document dirty = Jsoup.parseBodyFragment(line, baseUri);
        Document cleanedDoc = cleaner.clean(dirty);
        String cleanedB = cleanedDoc.body().html();

        if (!cleanedA.equals(cleanedB)) {
          diffs++;
        }

        bw.write(cleanedA);
        bw.newLine();
      }
    }

    System.out.println("Cleaned lines: " + lines + "; wrote -> " + outFile.getPath());
    if (diffs > 0) {
      System.err.println("Note: direct vs Cleaner outputs differed on " + diffs + " lines (kept direct Jsoup.clean)");
    }
  }
}
