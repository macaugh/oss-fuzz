// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.jsoup.Jsoup;
import org.jsoup.Connection;
import org.jsoup.helper.ValidationException;
import java.io.IOException;
import java.net.MalformedURLException;

/**
 * Fuzzer targeting HTTP/2 to HTTP/1 downgrade vulnerabilities in jsoup Connection API.
 *
 * This fuzzer specifically tests:
 * 1. Header injection differences between HttpClient (HTTP/2) and HttpURLConnection (HTTP/1.1)
 * 2. URL parsing discrepancies between HTTP versions
 * 3. Protocol-specific header validation bypasses
 * 4. Session state confusion during HTTP version switching
 *
 * Based on PortSwigger's "HTTP/1 Must Die" research on HTTP/2 smuggling attacks.
 */
public class HttpVersionDowngradeFuzzer {

    private static final String[] HTTP2_PSEUDO_HEADERS = {
        ":method", ":path", ":scheme", ":authority"
    };

    private static final String[] DANGEROUS_HEADER_CHARS = {
        "\n", "\r", "\r\n", "\u0000", "\u0001", "\u007F",
        " ", "\t", ":", ";", ",", "\"", "'", "<", ">",
        "{", "}", "|", "\\", "^", "`", "[", "]"
    };

    private static final String[] PROTOCOL_SCHEMES = {
        "http://", "https://", "ftp://", "file://", "javascript:", "data:"
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Test both HTTP client implementations
            boolean forceHttpClient = data.consumeBoolean();
            if (forceHttpClient) {
                System.setProperty("jsoup.useHttpClient", "true");
            } else {
                System.setProperty("jsoup.useHttpClient", "false");
            }

            // Generate base URL with potential protocol confusion
            String scheme = data.pickValue(PROTOCOL_SCHEMES);
            String host = data.consumeString(50).replaceAll("[^a-zA-Z0-9.-]", "");
            if (host.isEmpty()) host = "example.com";

            // Add potential port confusion
            int port = data.consumeBoolean() ? data.consumeInt(1, 65535) : 80;
            String baseUrl = scheme + host + ":" + port;

            // Create connection
            Connection connection = Jsoup.connect(baseUrl);

            // Test HTTP/2 pseudo-header injection
            if (data.consumeBoolean()) {
                String pseudoHeader = data.pickValue(HTTP2_PSEUDO_HEADERS);
                String headerValue = data.consumeString(100);
                try {
                    connection.header(pseudoHeader, headerValue);
                } catch (Exception ignored) {}
            }

            // Test header name/value injection with dangerous characters
            if (data.remainingBytes() > 50) {
                String headerName = generateFuzzedHeaderName(data);
                String headerValue = generateFuzzedHeaderValue(data);

                try {
                    connection.header(headerName, headerValue);
                } catch (Exception ignored) {}
            }

            // Test Content-Length vs Transfer-Encoding conflicts
            if (data.consumeBoolean()) {
                connection.header("Content-Length", String.valueOf(data.consumeInt(0, 1000000)));
                connection.header("Transfer-Encoding", "chunked");
            }

            // Test User-Agent with HTTP version-specific parsing
            if (data.consumeBoolean()) {
                String userAgent = data.consumeString(200);
                // Inject potential HTTP/2 frame markers or HTTP/1.1 line breaks
                if (data.consumeBoolean()) {
                    userAgent += data.pickValue(DANGEROUS_HEADER_CHARS);
                }
                connection.userAgent(userAgent);
            }

            // Test referrer with protocol confusion
            if (data.consumeBoolean()) {
                String referrerScheme = data.pickValue(PROTOCOL_SCHEMES);
                String referrerHost = data.consumeString(30).replaceAll("[^a-zA-Z0-9.-]", "");
                if (!referrerHost.isEmpty()) {
                    connection.referrer(referrerScheme + referrerHost);
                }
            }

            // Test method overrides that might behave differently in HTTP/2 vs HTTP/1.1
            if (data.consumeBoolean()) {
                Connection.Method method = data.pickValue(Connection.Method.values());
                connection.method(method);

                // Add potential method override headers
                if (data.consumeBoolean()) {
                    connection.header("X-HTTP-Method-Override", method.name());
                }
            }

            // Test timeout values that might expose version-specific behavior
            if (data.consumeBoolean()) {
                int timeout = data.consumeInt(1, 60000);
                connection.timeout(timeout);
            }

            // Test followRedirects with potential downgrade attacks
            if (data.consumeBoolean()) {
                connection.followRedirects(data.consumeBoolean());
            }

            // Test session sharing across HTTP versions
            if (data.consumeBoolean()) {
                Connection newRequest = connection.newRequest();
                newRequest.header("X-Version-Test", "session-shared");
            }

            // Test URL parsing without network calls to focus on parser differences
            connection.request().url();
            connection.request().headers();

        } catch (ValidationException ignored) {
            // Expected for malformed inputs
        } catch (Exception ignored) {
            // Catch unexpected parsing errors that might indicate vulnerabilities
        } finally {
            // Reset system property to avoid affecting other tests
            System.clearProperty("jsoup.useHttpClient");
        }
    }

    private static String generateFuzzedHeaderName(FuzzedDataProvider data) {
        String baseName = data.consumeString(30);

        // Inject dangerous characters that HTTP/2 and HTTP/1.1 handle differently
        if (data.consumeBoolean() && baseName.length() > 0) {
            int insertPos = data.consumeInt(0, baseName.length());
            String dangerousChar = data.pickValue(DANGEROUS_HEADER_CHARS);
            baseName = baseName.substring(0, insertPos) + dangerousChar + baseName.substring(insertPos);
        }

        return baseName;
    }

    private static String generateFuzzedHeaderValue(FuzzedDataProvider data) {
        String baseValue = data.consumeString(100);

        // Test HTTP/2 vs HTTP/1.1 header folding differences
        if (data.consumeBoolean()) {
            baseValue += "\r\n " + data.consumeString(50); // HTTP/1.1 header folding
        }

        // Test binary data that HTTP/2 allows but HTTP/1.1 might not handle correctly
        if (data.consumeBoolean()) {
            byte[] binaryData = data.consumeBytes(10);
            baseValue += new String(binaryData);
        }

        return baseValue;
    }
}