package harnesses;

// StreamParseFuzzer
// A pure, socket-free jsoup stream parsing fuzzer. It feeds fuzzed data through
// configurable, flaky InputStreams (chunked, early-close, IO exception) into
// Jsoup.parse(InputStream, ...) using both HTML and XML parsers. Optionally
// wraps the stream in GZIP/DEFLATE to stress decompression + stream parsing
// without involving java.net.http.

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.parser.Parser;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.InflaterInputStream;

public class StreamParseFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    if (input == null || input.length == 0) return;

    ByteBuffer bb = ByteBuffer.wrap(input);
    int f0 = bb.get() & 0xFF;              // parser + compression + behaviors
    int f1 = bb.hasRemaining() ? (bb.get() & 0xFF) : 0; // chunk/early-close config
    int f2 = bb.hasRemaining() ? (bb.get() & 0xFF) : 0; // charset/base toggles

    // Parser selection
    boolean xmlMode = (f0 & 0x01) != 0; // 0: HTML, 1: XML
    Parser parser = xmlMode ? Parser.xmlParser() : Parser.htmlParser();

    // Compression selection
    int compSel = (f0 >> 1) & 0x03; // 0 none, 1 gzip, 2 deflate
    boolean gzip = compSel == 1;
    boolean deflate = compSel == 2;

    // Stream behavior
    int chunkSel = (f1 & 0x03); // 0 large, 1 medium, 2 small, 3 single-byte
    boolean earlyClose = (f1 & 0x04) != 0; // close early
    boolean throwOnEOF = (f1 & 0x08) != 0; // throw IOException at end instead of -1
    int fractionSel = (f1 >> 4) & 0x03;    // early close fraction selector

    // Charset/base settings
    int csSel = (f2 & 0x03); // 0 null, 1 UTF-8, 2 ISO-8859-1, 3 UTF-16
    String charset = null;
    switch (csSel) {
      case 1: charset = StandardCharsets.UTF_8.name(); break;
      case 2: charset = StandardCharsets.ISO_8859_1.name(); break;
      case 3: charset = "UTF-16"; break;
      default: charset = null; break;
    }
    String baseUri = ((f2 & 0x04) != 0) ? "https://example.com/base/" : "";

    // Document bytes (rest)
    byte[] docBytes = new byte[bb.remaining()];
    bb.get(docBytes);
    if (docBytes.length == 0) {
      docBytes = (xmlMode ? "<?xml version=\"1.0\"?><root/>" : "<html><body>x</body></html>")
          .getBytes(StandardCharsets.UTF_8);
    }

    // Optionally add a BOM or meta charset hint to exercise charset handling
    if (!xmlMode && (f2 & 0x08) != 0) {
      String hint = "<meta charset=\"UTF-8\">";
      byte[] hintB = hint.getBytes(StandardCharsets.UTF_8);
      byte[] merged = new byte[hintB.length + docBytes.length];
      System.arraycopy(hintB, 0, merged, 0, hintB.length);
      System.arraycopy(docBytes, 0, merged, hintB.length, docBytes.length);
      docBytes = merged;
    }

    // Wrap bytes in compression if selected
    byte[] src = docBytes;
    if (gzip) src = compress(docBytes, true);
    if (deflate) src = compress(docBytes, false);

    // Controlled stream to simulate chunked/early-close/exceptional streams
    int chunkSize;
    switch (chunkSel) {
      case 1: chunkSize = 64; break;
      case 2: chunkSize = 8; break;
      case 3: chunkSize = 1; break;
      default: chunkSize = 512; break;
    }
    double frac;
    switch (fractionSel) {
      case 0: frac = 0.25; break;
      case 1: frac = 0.5; break;
      case 2: frac = 0.75; break;
      default: frac = 0.1; break;
    }
    int limitBytes = earlyClose ? Math.max(0, (int)Math.floor(src.length * frac)) : src.length;

    InputStream base = new ByteArrayInputStream(src);
    InputStream flaky = new FlakyChunkInputStream(base, chunkSize, limitBytes, throwOnEOF);

    // If compressed, present a decompressing stream to jsoup (mimicking HTTP layer)
    InputStream toParse;
    try {
      if (gzip) toParse = new GZIPInputStream(flaky, 512);
      else if (deflate) toParse = new InflaterInputStream(flaky);
      else toParse = flaky;
    } catch (IOException ioe) {
      return; // invalid compressed stream; treat as non-interesting
    }

    // Parse stream
    try {
      Document d = Jsoup.parse(toParse, charset, baseUri, parser);
      // Optionally traverse a bit to touch more code paths
      if (d != null && d.body() != null && (f0 & 0x80) != 0) {
        d.select("*").stream().limit(8).forEach(e -> {
          e.tagName(); e.attributes().size(); e.text();
        });
      }
    } catch (IllegalArgumentException e) {
      // ignore parse config errors
    } catch (java.io.UncheckedIOException e) {
      // benign stream failure
    } catch (RuntimeException re) {
      // surface real parser failures
      throw re;
    } catch (IOException e) {
      // thrown from GZIP/Inflater during read
    } finally {
      try { toParse.close(); } catch (IOException ignored) {}
    }
  }

  static byte[] compress(byte[] data, boolean useGzip) {
    try {
      java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
      OutputStream enc = useGzip ? new GZIPOutputStream(baos) : new DeflaterOutputStream(baos);
      enc.write(data);
      enc.close();
      return baos.toByteArray();
    } catch (IOException e) { return data; }
  }

  static final class FlakyChunkInputStream extends FilterInputStream {
    final int chunk;
    final int limit;
    final boolean throwOnEof;
    int readSoFar = 0;

    FlakyChunkInputStream(InputStream in, int chunkSize, int limitBytes, boolean throwOnEof) {
      super(in);
      this.chunk = Math.max(1, chunkSize);
      this.limit = Math.max(0, limitBytes);
      this.throwOnEof = throwOnEof;
    }

    @Override public int read() throws IOException {
      if (readSoFar >= limit) return end();
      int b = super.read();
      if (b >= 0) readSoFar++;
      return b;
    }

    @Override public int read(byte[] b, int off, int len) throws IOException {
      if (readSoFar >= limit) return end();
      int toRead = Math.min(len, Math.min(chunk, limit - readSoFar));
      int r = super.read(b, off, toRead);
      if (r > 0) readSoFar += r;
      return r;
    }

    private int end() throws IOException { if (throwOnEof) throw new IOException("EOF"); else return -1; }
  }
}

