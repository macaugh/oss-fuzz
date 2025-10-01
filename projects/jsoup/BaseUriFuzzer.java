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
import org.jsoup.helper.ValidationException;

public class BaseUriFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            String baseUri = data.consumeString(200);
            String html = data.consumeRemainingAsString();

            // Test different baseUri parsing methods
            switch (data.consumeInt(0, 2)) {
                case 0:
                    Jsoup.parse(html, baseUri);
                    break;
                case 1:
                    Jsoup.parseBodyFragment(html, baseUri);
                    break;
                case 2:
                    // Test relative URL resolution by accessing links
                    Jsoup.parse(html, baseUri).select("a[href]");
                    break;
            }
        } catch (ValidationException ignored) {
        }
    }
}
