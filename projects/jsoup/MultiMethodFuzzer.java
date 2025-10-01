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
import java.io.ByteArrayInputStream;

public class MultiMethodFuzzer {
    private static final String[] BASE_URLS = {
        "https://example.com", "http://test.org", "https://localhost:8080",
        "http://192.168.1.1", "https://api.test.com"
    };

    private static final Connection.Method[] HTTP_METHODS = {
        Connection.Method.GET, Connection.Method.POST, Connection.Method.PUT,
        Connection.Method.DELETE, Connection.Method.PATCH, Connection.Method.HEAD,
        Connection.Method.OPTIONS, Connection.Method.TRACE
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Generate URL
            String baseUrl = data.pickValue(BASE_URLS);
            String path = data.consumeString(100).replaceAll("[^a-zA-Z0-9._/?&=-]", "");
            String url = baseUrl + "/" + path;

            // Create connection
            Connection connection = Jsoup.connect(url);

            // Set HTTP method
            Connection.Method method = data.pickValue(HTTP_METHODS);
            connection.method(method);

            // Add basic connection settings
            if (data.consumeBoolean()) {
                connection.timeout(data.consumeInt(1000, 30000));
            }
            if (data.consumeBoolean()) {
                connection.userAgent(data.consumeString(100));
            }
            if (data.consumeBoolean()) {
                connection.followRedirects(data.consumeBoolean());
            }
            if (data.consumeBoolean()) {
                connection.ignoreHttpErrors(data.consumeBoolean());
            }
            if (data.consumeBoolean()) {
                connection.ignoreContentType(data.consumeBoolean());
            }

            // Add form data for POST/PUT/PATCH methods
            if (method == Connection.Method.POST || method == Connection.Method.PUT ||
                method == Connection.Method.PATCH) {

                // Add key-value form data
                while (data.remainingBytes() > 40 && data.consumeBoolean()) {
                    String key = data.consumeString(30);
                    String value = data.consumeString(100);
                    if (!key.trim().isEmpty()) {
                        connection.data(key, value);
                    }
                }

                // Optionally set raw request body
                if (data.consumeBoolean() && data.remainingBytes() > 20) {
                    String requestBody = data.consumeString(200);
                    connection.requestBody(requestBody);
                }

                // Test file upload simulation
                if (data.consumeBoolean() && data.remainingBytes() > 50) {
                    String fileName = data.consumeString(30);
                    String fileContent = data.consumeString(100);
                    String contentType = data.pickValue(new String[]{
                        "text/plain", "application/json", "application/xml",
                        "image/jpeg", "image/png", "application/pdf"
                    });

                    ByteArrayInputStream inputStream = new ByteArrayInputStream(fileContent.getBytes());
                    connection.data("file", fileName, inputStream, contentType);
                }

                // Set post data charset
                if (data.consumeBoolean()) {
                    String charset = data.pickValue(new String[]{
                        "UTF-8", "ISO-8859-1", "UTF-16", "ASCII"
                    });
                    connection.postDataCharset(charset);
                }
            }

            // Add headers
            while (data.remainingBytes() > 30 && data.consumeBoolean()) {
                String headerName = data.consumeString(30);
                String headerValue = data.consumeString(50);
                if (!headerName.trim().isEmpty()) {
                    connection.header(headerName, headerValue);
                }
            }

            // Add cookies
            while (data.remainingBytes() > 20 && data.consumeBoolean()) {
                String cookieName = data.consumeString(20);
                String cookieValue = data.consumeString(30);
                if (!cookieName.trim().isEmpty()) {
                    connection.cookie(cookieName, cookieValue);
                }
            }

            // Test request configuration access (without making actual network calls)
            Connection.Request request = connection.request();
            request.url();
            request.method();
            request.timeout();
            request.maxBodySize();
            request.followRedirects();
            request.ignoreHttpErrors();
            request.ignoreContentType();
            request.headers();
            request.cookies();

            // Test data access for form methods
            if (method == Connection.Method.POST || method == Connection.Method.PUT ||
                method == Connection.Method.PATCH) {
                request.requestBody();
                request.data();
                request.hasHeaderWithValue("Content-Type", "application/json");
            }

        } catch (IllegalArgumentException ignored) {
        }
    }
}