import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.helper.W3CDom;
import org.jsoup.helper.DataUtil;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class LoopRepro {
    public static void main(String[] args) throws Exception {
        // Replace with actual bad input that triggered your exception
	byte[] bytes = Files.readAllBytes(Path.of(args[0]));
	String html = new String(bytes, StandardCharsets.UTF_8);

        int failures = 0;
        for (int i = 0; i < 100_000; i++) {
            try {
                Jsoup.parseBodyFragment(html);
            } catch (Throwable t) {
                failures++;
            }

            if (i % 1000 == 0) {
                System.out.printf("iter=%d failures=%d%n", i, failures);
            }
        }

        System.out.println("done. total failures: " + failures);
        Thread.sleep(60_000); // keep JVM alive so you can inspect it
    }
}
