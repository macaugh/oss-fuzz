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

public class SessionFuzzer {
    private static final String[] BASE_URLS = {
        "https://example.com", "http://test.org", "https://localhost:8080",
        "http://192.168.1.1", "https://sub.domain.com", "https://api.test.com"
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Create session with fuzzed configuration
            Connection session = Jsoup.newSession();

            // Configure session settings
            if (data.consumeBoolean()) {
                session.timeout(data.consumeInt(1000, 60000));
            }
            if (data.consumeBoolean()) {
                session.userAgent(data.consumeString(200));
            }
            if (data.consumeBoolean()) {
                session.followRedirects(data.consumeBoolean());
            }
            if (data.consumeBoolean()) {
                session.ignoreHttpErrors(data.consumeBoolean());
            }
            if (data.consumeBoolean()) {
                session.ignoreContentType(data.consumeBoolean());
            }

            // Add headers to session
            while (data.remainingBytes() > 50 && data.consumeBoolean()) {
                String headerName = data.consumeString(50);
                String headerValue = data.consumeString(100);
                if (!headerName.trim().isEmpty() && !headerValue.trim().isEmpty()) {
                    session.header(headerName, headerValue);
                }
            }

            // Add cookies to session
            while (data.remainingBytes() > 30 && data.consumeBoolean()) {
                String cookieName = data.consumeString(30);
                String cookieValue = data.consumeString(50);
                if (!cookieName.trim().isEmpty()) {
                    session.cookie(cookieName, cookieValue);
                }
            }

            // Test creating requests from session
            if (data.remainingBytes() > 20) {
                String baseUrl = data.pickValue(BASE_URLS);
                String path = data.consumeString(50).replaceAll("[^a-zA-Z0-9._/-]", "");
                String fullUrl = baseUrl + "/" + path;

                Connection request = session.newRequest(fullUrl);

                // Configure request-specific settings
                if (data.consumeBoolean() && data.remainingBytes() > 10) {
                    String requestHeader = data.consumeString(30);
                    String requestValue = data.consumeString(30);
                    if (!requestHeader.trim().isEmpty()) {
                        request.header(requestHeader, requestValue);
                    }
                }

                // Test URL parsing without making actual network request
                request.request().url();
            }

        } catch (ValidationException ignored) {
        }
    }
}
