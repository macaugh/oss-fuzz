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
import org.jsoup.parser.Parser;
import org.jsoup.parser.ParseSettings;

public class ConfigurationFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            String html = data.consumeRemainingAsString();

            // Create parser with various configurations
            Parser parser = data.consumeBoolean() ? Parser.htmlParser() : Parser.xmlParser();

            // Configure ParseSettings
            ParseSettings settings = new ParseSettings(
                data.consumeBoolean(), // preserve case
                data.consumeBoolean()  // preserve attribute case
            );
            parser.settings(settings);

            // Configure error tracking
            if (data.consumeBoolean()) {
                parser.setTrackErrors(data.consumeInt(0, 100));
            }

            // Parse with configured parser
            Document doc = Jsoup.parse(html, "", parser);

            // Configure OutputSettings and test serialization
            Document.OutputSettings outputSettings = doc.outputSettings();

            if (data.consumeBoolean()) {
                outputSettings.prettyPrint(data.consumeBoolean());
            }
            if (data.consumeBoolean()) {
                outputSettings.outline(data.consumeBoolean());
            }
            if (data.consumeBoolean()) {
                outputSettings.indentAmount(data.consumeInt(0, 10));
            }
            if (data.consumeBoolean()) {
                Document.OutputSettings.EscapeMode[] modes = Document.OutputSettings.EscapeMode.values();
                outputSettings.escapeMode(modes[data.consumeInt(0, modes.length - 1)]);
            }
            if (data.consumeBoolean()) {
                outputSettings.charset(data.pickValue(new String[]{"UTF-8", "ISO-8859-1", "ASCII"}));
            }

            // Test serialization with configured settings
            doc.html();

            // Test error tracking results if enabled
            if (parser.isTrackErrors() && parser.getErrors().size() > 0) {
                parser.getErrors().get(0).toString();
            }

        } catch (ValidationException ignored) {
        }
    }
}
