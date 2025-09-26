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
import org.jsoup.parser.Parser;
import org.jsoup.parser.ParseSettings;

public class AdvancedHTMLFuzzer {
    private static final String[] HTML_PREFIXES = {
        "<!DOCTYPE html>",
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">",
        "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        ""
    };

    private static final String[] COMPLEX_HTML_STRUCTURES = {
        "<html><head><meta charset='utf-8'><title>Test</title></head><body>",
        "<table><thead><tr><th>Header</th></tr></thead><tbody><tr><td>Data</td></tr></tbody></table>",
        "<form method='post' action='/submit'><fieldset><legend>Form</legend><input type='text' name='field'></fieldset></form>",
        "<svg width='100' height='100'><circle cx='50' cy='50' r='40'/></svg>",
        "<script type='text/javascript'>var x = 1;</script><style>body{margin:0}</style>",
        "<iframe src='about:blank' width='100' height='100'></iframe>",
        "<details><summary>Click me</summary><p>Hidden content</p></details>",
        "<template><div class='template-content'>Template</div></template>"
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Build complex HTML structure
            StringBuilder htmlBuilder = new StringBuilder();

            // Add DOCTYPE or XML declaration
            if (data.consumeBoolean()) {
                htmlBuilder.append(data.pickValue(HTML_PREFIXES));
            }

            // Add one or more complex structures
            int structureCount = data.consumeInt(1, 3);
            for (int i = 0; i < structureCount && data.remainingBytes() > 100; i++) {
                htmlBuilder.append(data.pickValue(COMPLEX_HTML_STRUCTURES));
            }

            // Add fuzzed content
            htmlBuilder.append(data.consumeString(500));

            // Close any open tags
            htmlBuilder.append("</body></html>");

            String html = htmlBuilder.toString();

            // Create parser with various configurations
            Parser parser;
            if (data.consumeBoolean()) {
                parser = Parser.htmlParser();
            } else {
                parser = Parser.xmlParser();
            }

            // Configure parse settings
            ParseSettings settings = new ParseSettings(
                data.consumeBoolean(), // preserve case
                data.consumeBoolean()  // preserve attribute case
            );
            parser.settings(settings);

            // Configure error tracking
            if (data.consumeBoolean()) {
                parser.setTrackErrors(data.consumeInt(0, 100));
            }

            // Parse the document
            String baseUri = data.consumeBoolean() ? "https://example.com" : "";
            Document doc = parser.parseInput(html, baseUri);

            // Test various document operations
            while (data.remainingBytes() > 10) {
                int operation = data.consumeInt(0, 12);

                switch (operation) {
                    case 0: // Test document structure
                        doc.head();
                        doc.body();
                        doc.title();
                        break;

                    case 1: // Test meta information
                        doc.select("meta[charset]");
                        doc.select("meta[name=viewport]");
                        doc.select("link[rel=stylesheet]");
                        break;

                    case 2: // Test form handling
                        doc.select("form").forEach(form -> {
                            form.select("input, textarea, select");
                            form.attr("method");
                            form.attr("action");
                        });
                        break;

                    case 3: // Test table handling
                        doc.select("table").forEach(table -> {
                            table.select("thead th");
                            table.select("tbody td");
                            table.select("tr");
                        });
                        break;

                    case 4: // Test script and style handling
                        doc.select("script").forEach(script -> {
                            script.data();
                            script.attr("type");
                            script.attr("src");
                        });
                        doc.select("style").forEach(style -> {
                            style.data();
                        });
                        break;

                    case 5: // Test multimedia content
                        doc.select("img, video, audio, iframe").forEach(media -> {
                            media.attr("src");
                            media.attr("width");
                            media.attr("height");
                        });
                        break;

                    case 6: // Test semantic HTML5 elements
                        doc.select("article, section, nav, aside, header, footer, main").forEach(semantic -> {
                            semantic.text();
                            semantic.children();
                        });
                        break;

                    case 7: // Test list structures
                        doc.select("ul, ol").forEach(list -> {
                            list.select("li");
                        });
                        doc.select("dl").forEach(dl -> {
                            dl.select("dt, dd");
                        });
                        break;

                    case 8: // Test text content extraction
                        doc.text();
                        doc.wholeText();
                        doc.ownText();
                        break;

                    case 9: // Configure and test output settings
                        Document.OutputSettings outputSettings = doc.outputSettings();
                        outputSettings.prettyPrint(data.consumeBoolean());
                        outputSettings.outline(data.consumeBoolean());
                        outputSettings.indentAmount(data.consumeInt(0, 8));

                        if (data.consumeBoolean()) {
                            Entities.EscapeMode[] modes = Entities.EscapeMode.values();
                            outputSettings.escapeMode(modes[data.consumeInt(0, modes.length - 1)]);
                        }

                        if (data.consumeBoolean()) {
                            outputSettings.charset(data.pickValue(new String[]{"UTF-8", "ISO-8859-1", "ASCII"}));
                        }

                        // Test output with configured settings
                        doc.html();
                        break;

                    case 10: // Test error tracking
                        if (parser.isTrackErrors() && !parser.getErrors().isEmpty()) {
                            parser.getErrors().forEach(error -> {
                                error.getErrorMessage();
                                error.getPosition();
                            });
                        }
                        break;

                    case 11: // Test special characters and entities
                        doc.select("*").forEach(elem -> {
                            elem.html().contains("&");
                            elem.text().length();
                        });
                        break;

                    case 12: // Test document cloning
                        Document clone = doc.clone();
                        clone.html(); // Test that clone works
                        break;
                }

                if (data.consumeBoolean()) break;
            }

        } catch (ValidationException ignored) {
        } catch (IllegalArgumentException ignored) {
        }
    }
}