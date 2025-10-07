package harnesses;
// JsoupConnectFuzzer.java
// Basic Jazzer fuzzer for jsoup's Connection API (Jsoup.connect(...)).
// Safely exercises HTTP fetching against a local in-process HTTP server so the
// fuzzer never reaches the public network and responses are fully controlled by
// the input bytes.

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.jsoup.Connection;
import org.jsoup.Jsoup;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Locale;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;
import java.util.zip.DeflaterOutputStream;

public class JsoupConnectFuzzer {
  private static HttpServer server;
  private static int port;
  private static final AtomicReference<Config> cfgRef = new AtomicReference<>();

  public static void fuzzerInitialize() throws Exception {
    if (server != null) return;
    // Allow network connections to loopback only to avoid SSRF bug detector noise.
    // Allow network connections via reflection if BugDetectors API is available; ignore otherwise.
    try {
      Class<?> bd = Class.forName("com.code_intelligence.jazzer.api.BugDetectors");
      try {
        // Newer API: no-arg
        bd.getMethod("allowNetworkConnections").invoke(null);
      } catch (NoSuchMethodException e) {
        // Older API variant: with Predicate<String>
        try {
          java.util.function.Predicate<String> pred = host -> host != null && (
              host.contains("127.0.0.1") || host.contains("localhost") || host.contains("::1") || host.contains("[::1]")
          );
          bd.getMethod("allowNetworkConnections", Class.forName("java.util.function.Predicate")).invoke(null, pred);
        } catch (Throwable inner) {
          // ignore
        }
      }
    } catch (Throwable ignored) {
      // BugDetectors not available; rely on --disabled_hooks flag in runner.
    }
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    port = server.getAddress().getPort();
    server.createContext("/", new Handler());
    server.setExecutor(Executors.newFixedThreadPool(2));
    server.start();
  }

  public static void fuzzerTestOneInput(byte[] input) {
    if (server == null) {
      try { fuzzerInitialize(); } catch (Exception ignored) {}
    }
    if (input == null || input.length == 0) return;

    ByteBuffer bb = ByteBuffer.wrap(input);
    int flags;
    int flags2;
    // Support deterministic flag override via textual header: "FLAGS:xx:yy\n"
    // where xx and yy are two hex bytes.
    try {
      String s = new String(input, 0, Math.min(input.length, 64), StandardCharsets.US_ASCII);
      if (s.startsWith("FLAGS:") && s.indexOf('\n') > 0) {
        int nl = s.indexOf('\n');
        String hdr = s.substring(6, nl).trim();
        String[] parts = hdr.split("[: ,]");
        if (parts.length >= 2) {
          flags = Integer.parseInt(parts[0], 16) & 0xFF;
          flags2 = Integer.parseInt(parts[1], 16) & 0xFF;
          // Remaining body after newline
          byte[] rest = java.util.Arrays.copyOfRange(input, nl + 1, input.length);
          bb = ByteBuffer.wrap(rest);
        } else {
          flags = (bb.get() & 0xFF);
          flags2 = (bb.hasRemaining() ? (bb.get() & 0xFF) : 0);
        }
      } else {
        flags = (bb.get() & 0xFF);
        flags2 = (bb.hasRemaining() ? (bb.get() & 0xFF) : 0);
      }
    } catch (Exception e) {
      flags = (bb.get() & 0xFF);
      flags2 = (bb.hasRemaining() ? (bb.get() & 0xFF) : 0);
    }
    // Hard-code conservative, stable settings to avoid spurious timeouts.
    final int timeoutMs = 5000;              // generous but bounded
    final int maxBody = 64 * 1024;           // cap response body read

    // Still vary server-side behavior/content-type a bit, but keep client stable.
    boolean doRedirect = (flags & 0x01) != 0;
    int ctSel = (flags >> 1) & 0x03;
    boolean gzipEnc = (flags & 0x04) != 0;
    boolean deflateEnc = !gzipEnc && ((flags & 0x08) != 0);
    boolean chunked = (flags & 0x10) != 0;
    int statusSel = (flags >> 5) & 0x07; // 0..7 -> map to common statuses
    // Secondary flags controlling malformed transfer behaviors
    int lenMode = (flags2 & 0x03);              // 0=normal, 1=header>actual, 2=header<actual, 3=early-close
    boolean malformedChunked = (flags2 & 0x04) != 0; // if chunked, omit proper termination
    int partialSel = (flags2 >> 3) & 0x03;      // how much to write in early/partial cases

    String body = StandardCharsets.UTF_8.decode(bb.slice()).toString();
    if (body.isEmpty()) body = "<html><title>t</title><body>x</body></html>";

    Config cfg = new Config();
    cfg.body = body;
    cfg.redirect = doRedirect;
    cfg.contentTypeIdx = ctSel;
    cfg.gzip = gzipEnc;
    cfg.deflate = deflateEnc;
    cfg.chunked = chunked;
    cfg.status = pickStatus(statusSel, doRedirect);
    cfg.duplicateCT = (flags & 0x80) != 0; // add duplicate Content-Type header
    cfg.lenMode = lenMode;
    cfg.malformedChunked = malformedChunked;
    cfg.partialSel = partialSel;
    cfgRef.set(cfg);

    // Always target loopback to avoid external network; URL host is constant to prevent SSRF taint
    String url = "http://127.0.0.1:" + port + (doRedirect ? "/redir?n=0" : "/doc?q=1");

    try {
      Connection con = Jsoup.connect(url)
          .timeout(timeoutMs)
          .maxBodySize(maxBody)
          .followRedirects(true)
          .ignoreContentType(true)
          .ignoreHttpErrors(true)
          .userAgent("Jazzer/JsoupConnectFuzzer")
          .referrer("http://127.0.0.1:")
          .header("X-Fuzz", Integer.toString(flags));

      // Use GET consistently to minimize I/O corner cases.
      con.method(Connection.Method.GET);

      // Execute; on HTML types, also parse with get() sometimes
      Connection.Response resp = con.execute();
      String ct = resp.contentType() != null ? resp.contentType().toLowerCase(Locale.ROOT) : "";
      boolean looksXml = (ct.contains("xml") || ct.contains("svg"));
      // Exercise stream parsing using the response body stream, selecting parser by content-type.
      try (java.io.InputStream in = resp.bodyStream()) {
        org.jsoup.parser.Parser parser = looksXml ? org.jsoup.parser.Parser.xmlParser() : org.jsoup.parser.Parser.htmlParser();
        try {
          Jsoup.parse(in, null, url, parser);
        } catch (java.io.UncheckedIOException uioe) {
          // Treat read timeouts and I/O as benign in this harness.
        }
      }
    } catch (IllegalArgumentException | IOException ignored) {
      // expected in many cases (timeouts, parse errors, etc.)
    } catch (RuntimeException re) {
      // Ignore UncheckedIOException as non-buggy environmental timeouts.
      if (re instanceof java.io.UncheckedIOException) return;
      throw re;
    }
  }

  private static String pickContentType(int idx) {
    switch (idx & 3) {
      case 0: return "text/html; charset=UTF-8";
      case 1: return "image/svg+xml";
      case 2: return "application/xml";
      default: return "text/plain";
    }
  }

  private static class Config {
    String body;
    boolean redirect;
    int contentTypeIdx;
    boolean gzip;
    boolean deflate;
    boolean chunked;
    int status;
    boolean duplicateCT;
    int lenMode;
    boolean malformedChunked;
    int partialSel;
  }

  private static class Handler implements HttpHandler {
    @Override public void handle(HttpExchange ex) throws IOException {
      Config cfg = cfgRef.get();
      if (cfg == null) cfg = new Config();

      URI uri = ex.getRequestURI();
      String path = uri.getPath();
      Headers h = ex.getResponseHeaders();

      if (cfg.redirect && path != null && path.startsWith("/redir")) {
        int n = 0;
        try {
          String q = uri.getRawQuery();
          if (q != null && q.contains("n=")) {
            String nv = q.substring(q.indexOf("n=") + 2);
            int amp = nv.indexOf('&');
            if (amp >= 0) nv = nv.substring(0, amp);
            n = Integer.parseInt(URLDecoder.decode(nv, StandardCharsets.UTF_8.name()));
          }
        } catch (Exception ignored) {}
        if (n < 2) {
          h.add("Location", "/redir?n=" + (n + 1));
          ex.sendResponseHeaders(302, -1);
          ex.close();
          return;
        }
      }

      String ct = pickContentType(cfg.contentTypeIdx);
      ArrayList<String> ctVals = new ArrayList<>();
      ctVals.add(ct);
      if (cfg.duplicateCT) ctVals.add(ct + "; charset=ISO-8859-1");
      for (String v : ctVals) h.add("Content-Type", v);

      // Status code selection
      int status = cfg.status;
      if (status == 301 || status == 302 || status == 307 || status == 308) {
        h.add("Location", "/doc?q=redir");
      }

      byte[] bytes = (cfg.body != null ? cfg.body : "").getBytes(StandardCharsets.UTF_8);
      boolean noBody = (status == 204);
      boolean chunked = cfg.chunked;
      boolean gzip = cfg.gzip;
      boolean deflate = cfg.deflate;
      if (gzip) h.add("Content-Encoding", "gzip");
      if (deflate) h.add("Content-Encoding", "deflate");

      // Decide declared Content-Length
      long declaredLen;
      if (noBody) {
        declaredLen = -1;
      } else if (chunked || gzip || deflate) {
        declaredLen = -1; // chunked/encoded
      } else {
        int delta = Math.max(1, bytes.length / 4);
        switch (cfg.lenMode) {
          case 1: declaredLen = bytes.length + delta; break; // header bigger than actual write
          case 2: declaredLen = Math.max(0, bytes.length - delta); break; // header smaller than actual write
          default: declaredLen = bytes.length; break;
        }
      }

      ex.sendResponseHeaders(status, declaredLen);
      if (!noBody) {
        OutputStream os = ex.getResponseBody();
        OutputStream enc = gzip ? new GZIPOutputStream(os) : deflate ? new DeflaterOutputStream(os) : os;
        try {
          // Determine how many bytes to actually write
          int writeLen = bytes.length;
          if (cfg.lenMode == 3) { // early close: write partial
            int frac;
            switch (cfg.partialSel & 0x03) {
              case 0: frac = 1; break;   // 1/4
              case 1: frac = 2; break;   // 1/2
              case 2: frac = 3; break;   // 3/4
              default: frac = 0; break;  // minimal
            }
            writeLen = Math.max(0, (bytes.length * frac) / 4);
          }
          if (chunked && cfg.malformedChunked && !gzip && !deflate) {
            // Simulate truncated chunked body by writing only part and exiting without closing enc
            int off = 0;
            int step = Math.max(1, Math.max(1, writeLen) / 3);
            while (off < writeLen) {
              int end = Math.min(writeLen, off + step);
              enc.write(bytes, off, end - off);
              off = end;
              if (off >= writeLen) break;
            }
            // Do not close enc, leave truncation to connection close
          } else {
            enc.write(bytes, 0, writeLen);
            enc.flush();
          }
        } finally {
          try { enc.close(); } catch (Exception ignored) {}
        }
      }
    }
  }

  private static int pickStatus(int sel, boolean wantRedirect) {
    int[] normals = new int[]{200, 204, 400, 500};
    int[] redirs = new int[]{301, 302, 307, 308};
    if (wantRedirect) return redirs[sel % redirs.length];
    return normals[sel % normals.length];
  }
}
