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
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Entities;
import org.jsoup.safety.Safelist;

public class CleanerFuzzer {
    private static final Safelist[] SAFELISTS = {
        Safelist.none(),
        Safelist.simpleText(),
        Safelist.basic(),
        Safelist.basicWithImages(),
        Safelist.relaxed()
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            String baseUri = data.consumeString(100);
            String html = data.consumeRemainingAsString();

            // Choose a random safelist
            Safelist safelist = SAFELISTS[data.consumeInt(0, SAFELISTS.length - 1)];

            // Test different cleaning methods
            switch (data.consumeInt(0, 3)) {
                case 0:
                    Jsoup.clean(html, safelist);
                    break;
                case 1:
                    Jsoup.clean(html, baseUri, safelist);
                    break;
                case 2:
                    Document.OutputSettings outputSettings = new Document.OutputSettings();
                    outputSettings.escapeMode(Entities.EscapeMode.xhtml);
                    Jsoup.clean(html, baseUri, safelist, outputSettings);
                    break;
                case 3:
                    // Test validation
                    Jsoup.isValid(html, safelist);
                    break;
            }
        } catch (ValidationException ignored) {
        }
    }
}
