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

public class ConnectionFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            String url = data.consumeString(200);
            String userAgent = data.consumeString(100);
            String referrer = data.consumeString(100);
            int timeout = data.consumeInt(1, 30000);

            // Test Connection building and configuration
            Connection connection = Jsoup.connect(url);

            // Configure connection with fuzzed data
            if (data.consumeBoolean()) {
                connection.userAgent(userAgent);
            }
            if (data.consumeBoolean()) {
                connection.referrer(referrer);
            }
            if (data.consumeBoolean()) {
                connection.timeout(timeout);
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

            // Add headers if remaining data
            if (data.remainingBytes() > 20) {
                String headerName = data.consumeString(50);
                String headerValue = data.consumeString(50);
                connection.header(headerName, headerValue);
            }

            // Test URL parsing without actual network call
            connection.request().url();

        } catch (ValidationException ignored) {
        }
    }
}
