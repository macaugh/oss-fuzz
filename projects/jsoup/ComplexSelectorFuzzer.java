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
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.jsoup.select.Selector;

public class ComplexSelectorFuzzer {
    private static final String[] SAMPLE_HTML_BASES = {
        "<div class='container'><p id='test'>Text</p><span class='highlight'>More</span></div>",
        "<table><tr><td class='cell'>Data</td></tr></table>",
        "<form><input name='field' type='text' value='data'><button>Submit</button></form>",
        "<ul><li class='item first'>Item 1</li><li class='item'>Item 2</li></ul>",
        "<article><header><h1>Title</h1></header><section><p>Content</p></section></article>"
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Choose base HTML structure
            String baseHtml = data.pickValue(SAMPLE_HTML_BASES);

            // Add fuzzed content
            String additionalHtml = data.consumeString(500);
            String fullHtml = baseHtml + additionalHtml;

            // Parse document
            Document doc = Jsoup.parse(fullHtml);

            // Generate and test CSS selectors
            String selector = generateSelector(data);
            if (selector != null && !selector.trim().isEmpty()) {
                // Test various selector methods
                switch (data.consumeInt(0, 4)) {
                    case 0:
                        doc.select(selector);
                        break;
                    case 1:
                        doc.selectFirst(selector);
                        break;
                    case 2:
                        Elements elements = doc.select(selector);
                        if (!elements.isEmpty()) {
                            elements.first().text();
                        }
                        break;
                    case 3:
                        Elements allElements = doc.select(selector);
                        for (Element element : allElements) {
                            element.tagName();
                            if (data.consumeBoolean()) break;
                        }
                        break;
                    case 4:
                        // Test selector compilation directly
                        Selector.select(selector, doc);
                        break;
                }
            }

        } catch (ValidationException | Selector.SelectorParseException ignored) {
        }
    }

    private static String generateSelector(FuzzedDataProvider data) {
        StringBuilder selector = new StringBuilder();

        // Generate different types of selectors
        switch (data.consumeInt(0, 6)) {
            case 0: // Element selectors
                selector.append(data.pickValue(new String[]{"div", "p", "span", "a", "table", "tr", "td", "li", "input", "button"}));
                break;
            case 1: // Class selectors
                selector.append(".").append(data.consumeString(20).replaceAll("[^a-zA-Z0-9_-]", ""));
                break;
            case 2: // ID selectors
                selector.append("#").append(data.consumeString(20).replaceAll("[^a-zA-Z0-9_-]", ""));
                break;
            case 3: // Attribute selectors
                String attrName = data.consumeString(20).replaceAll("[^a-zA-Z0-9_-]", "");
                String attrValue = data.consumeString(30);
                String attrOp = data.pickValue(new String[]{"", "=", "^=", "$=", "*=", "~=", "|="});
                selector.append("[").append(attrName);
                if (!attrOp.isEmpty()) {
                    selector.append(attrOp).append("\"").append(attrValue).append("\"");
                }
                selector.append("]");
                break;
            case 4: // Pseudo selectors
                String pseudo = data.pickValue(new String[]{
                    ":first-child", ":last-child", ":nth-child(odd)", ":nth-child(even)",
                    ":nth-child(2n+1)", ":first-of-type", ":last-of-type", ":only-child",
                    ":empty", ":root", ":not(p)", ":has(span)"
                });
                selector.append("*").append(pseudo);
                break;
            case 5: // Combinators
                String elem1 = data.pickValue(new String[]{"div", "p", "span", "li"});
                String combinator = data.pickValue(new String[]{" ", ">", "+", "~"});
                String elem2 = data.pickValue(new String[]{"a", "span", "input", "button"});
                selector.append(elem1).append(combinator).append(elem2);
                break;
            case 6: // Complex multi-part selectors
                selector.append(data.consumeRemainingAsString());
                break;
        }

        return selector.toString();
    }
}