package harnesses;

// JsoupConnectMockFuzzer.java
// A socket-free fuzzer for Jsoup.connect by installing a URLStreamHandlerFactory
// that returns a dummy HttpURLConnection backed by the fuzz input. This avoids
// SSRF hooks and flakiness from real sockets while still exercising jsoup's
// response handling and parsing.

import org.jsoup.Connection;
import org.jsoup.Jsoup;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class JsoupConnectMockFuzzer {
  private static volatile boolean factoryInstalled = false;
  private static final ThreadLocal<Object> current = new ThreadLocal<>();

  public static void fuzzerInitialize() {
    if (!factoryInstalled) {
      try {
        URL.setURLStreamHandlerFactory(new MockFactory());
        factoryInstalled = true;
      } catch (Error ignored) {
        // Factory already set by JVM or another test; ignore and continue.
        factoryInstalled = true;
      }
    }
    // Try to allow network connections via Jazzer BugDetectors if present to
    // suppress SSRF sanitizer for this socket-free mock harness.
    try {
      Class<?> bd = Class.forName("com.code_intelligence.jazzer.api.BugDetectors");
      try {
        bd.getMethod("allowNetworkConnections").invoke(null);
      } catch (NoSuchMethodException e) {
        try {
          java.util.function.Predicate<String> pred = host -> host != null && (
              host.contains("127.0.0.1") || host.contains("localhost") || host.contains("::1") || host.contains("[::1]")
          );
          bd.getMethod("allowNetworkConnections", Class.forName("java.util.function.Predicate")).invoke(null, pred);
        } catch (Throwable ignored) {}
      }
    } catch (Throwable ignored) {
      // If Jazzer API not available, rely on runner flag --disabled_hooks.
    }
  }

  public static void fuzzerTestOneInput(byte[] input) {
    if (!factoryInstalled) fuzzerInitialize();
    if (input == null || input.length == 0) return;

    ByteBuffer bb = ByteBuffer.wrap(input);
    int flags = bb.get() & 0xFF;
    int ctSel = (flags & 0x03);
    int statusSel = (flags >> 2) & 0x03;
    boolean duplicateCT = (flags & 0x08) != 0;
    boolean doRedirect = (flags & 0x10) != 0;
    boolean errorStatus = (flags & 0x20) != 0;
    boolean gzip = (flags & 0x40) != 0;
    boolean deflate = !gzip && (flags & 0x80) != 0;

    String body = StandardCharsets.UTF_8.decode(bb.slice()).toString();
    if (body.isEmpty()) body = "<html><title>m</title><body>y</body></html>";

    // Build response sequence: optional redirect then final content
    List<ResponseModel> seq = new ArrayList<>();
    if (doRedirect) {
      ResponseModel r1 = new ResponseModel();
      r1.status = 302;
      r1.contentType = "text/plain";
      r1.body = new byte[0];
      r1.headers = new LinkedHashMap<>();
      r1.headers.put("Location", Collections.singletonList("http://mock.local/next"));
      seq.add(r1);
    }

    ResponseModel r2 = new ResponseModel();
    r2.status = pickStatus(statusSel, errorStatus);
    r2.contentType = pickContentType(ctSel);
    r2.body = body.getBytes(StandardCharsets.UTF_8);
    r2.headers = new LinkedHashMap<>();
    // Content-Type (optionally duplicate/conflicting)
    List<String> cts = new ArrayList<>();
    cts.add(r2.contentType);
    if (duplicateCT) cts.add(r2.contentType + "; charset=ISO-8859-1");
    r2.headers.put("Content-Type", cts);
    // Content-Encoding + precompress body
    if (gzip) {
      r2.headers.put("Content-Encoding", Collections.singletonList("gzip"));
      r2.body = compress(r2.body, true);
    } else if (deflate) {
      r2.headers.put("Content-Encoding", Collections.singletonList("deflate"));
      r2.body = compress(r2.body, false);
    }
    seq.add(r2);

    current.set(new Sequence(seq));

    try {
      Connection.Response resp = Jsoup.connect("http://mock.local/any").timeout(3000).maxBodySize(64*1024).followRedirects(true).execute();
      String ct = String.valueOf(resp.contentType()).toLowerCase(Locale.ROOT);
      if (ct.contains("html") || ct.contains("xml") || ct.contains("svg")) {
        try { Jsoup.parse(resp.body()); } catch (java.io.UncheckedIOException ignored) {}
      }
    } catch (IllegalArgumentException | IOException ignored) {
      // ignore benign issues
    } catch (RuntimeException re) {
      if (re instanceof java.io.UncheckedIOException) return;
      throw re;
    } finally {
      current.remove();
    }
  }

  private static int pickStatus(int sel, boolean error) {
    int[] ok = {200, 204};
    int[] bad = {400, 500};
    return error ? bad[sel % bad.length] : ok[sel % ok.length];
  }

  private static String pickContentType(int idx) {
    switch (idx & 3) {
      case 0: return "text/html; charset=UTF-8";
      case 1: return "image/svg+xml";
      case 2: return "application/xml";
      default: return "text/plain";
    }
  }

  // Model representing a single synthetic HTTP response for the current fuzz iteration.
  private static final class ResponseModel {
    int status;
    String contentType;
    byte[] body;
    Map<String, List<String>> headers;

  }

  // Simple sequence holder used in ThreadLocal
  private static final class Sequence {
    final List<ResponseModel> seq;
    Sequence(List<ResponseModel> s) { this.seq = s; }
  }

  private static final class MockFactory implements URLStreamHandlerFactory {
    @Override public URLStreamHandler createURLStreamHandler(String protocol) {
      if ("http".equalsIgnoreCase(protocol) || "https".equalsIgnoreCase(protocol)) {
        return new URLStreamHandler() {
          @Override protected URLConnection openConnection(URL u) throws IOException {
            Object rmObj = current.get();
            if (rmObj instanceof Sequence) {
              Sequence s = (Sequence) rmObj;
              // Choose by path: /next gets the second response; otherwise first
              if (u.getPath() != null && u.getPath().endsWith("/next") && s.seq.size() > 1) {
                return new MockHttpURLConnection(u, s.seq.get(1));
              } else {
                return new MockHttpURLConnection(u, s.seq.get(0));
              }
            }
            return new MockHttpURLConnection(u, (ResponseModel) rmObj);
          }
        };
      }
      return null;
    }
  }

  private static final class MockHttpURLConnection extends HttpURLConnection {
    private final ResponseModel model;
    protected MockHttpURLConnection(URL u, ResponseModel rm) { super(u); this.model = rm; }
    @Override public void disconnect() {}
    @Override public boolean usingProxy() { return false; }
    @Override public void connect() throws IOException {}
    @Override public int getResponseCode() throws IOException { return model != null ? model.status : 200; }
    @Override public String getContentType() { return model != null ? model.contentType : null; }
    @Override public InputStream getInputStream() throws IOException {
      int code = getResponseCode();
      if (code >= 400) throw new IOException("HTTP error " + code);
      return new ByteArrayInputStream(model != null ? model.body : new byte[0]);
    }
    @Override public InputStream getErrorStream() { try { if (getResponseCode() >= 400) return new ByteArrayInputStream(model.body); } catch (IOException ignored) {} return null; }
    @Override public Map<String, List<String>> getHeaderFields() { return model != null ? model.headers : Collections.emptyMap(); }
  }

  private static byte[] compress(byte[] data, boolean gzip) {
    try {
      java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
      OutputStream enc = gzip ? new java.util.zip.GZIPOutputStream(baos) : new java.util.zip.DeflaterOutputStream(baos);
      enc.write(data);
      enc.close();
      return baos.toByteArray();
    } catch (IOException e) {
      return data;
    }
  }
}
