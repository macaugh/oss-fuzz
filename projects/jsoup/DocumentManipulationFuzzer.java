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

public class DocumentManipulationFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            String html = data.consumeString(500);
            Document doc = Jsoup.parse(html);

            // Perform various DOM manipulation operations
            while (data.remainingBytes() > 10) {
                int operation = data.consumeInt(0, 15);

                switch (operation) {
                    case 0: // Text manipulation
                        Elements elements = doc.select("*");
                        if (!elements.isEmpty()) {
                            Element elem = elements.get(data.consumeInt(0, elements.size() - 1));
                            if (data.consumeBoolean()) {
                                elem.text(data.consumeString(100));
                            } else {
                                elem.text();
                            }
                        }
                        break;

                    case 1: // HTML manipulation
                        Elements htmlElems = doc.select("*");
                        if (!htmlElems.isEmpty()) {
                            Element elem = htmlElems.get(data.consumeInt(0, htmlElems.size() - 1));
                            if (data.consumeBoolean()) {
                                elem.html(data.consumeString(200));
                            } else {
                                elem.html();
                            }
                        }
                        break;

                    case 2: // Attribute manipulation
                        Elements attrElems = doc.select("*");
                        if (!attrElems.isEmpty()) {
                            Element elem = attrElems.get(data.consumeInt(0, attrElems.size() - 1));
                            String attrName = data.consumeString(30);
                            if (data.consumeBoolean()) {
                                elem.attr(attrName, data.consumeString(50));
                            } else {
                                elem.attr(attrName);
                                elem.removeAttr(attrName);
                            }
                        }
                        break;

                    case 3: // Class manipulation
                        Elements classElems = doc.select("*");
                        if (!classElems.isEmpty()) {
                            Element elem = classElems.get(data.consumeInt(0, classElems.size() - 1));
                            String className = data.consumeString(30);
                            switch (data.consumeInt(0, 2)) {
                                case 0: elem.addClass(className); break;
                                case 1: elem.removeClass(className); break;
                                case 2: elem.toggleClass(className); break;
                            }
                        }
                        break;

                    case 4: // Element creation and addition
                        Elements parents = doc.select("*");
                        if (!parents.isEmpty()) {
                            Element parent = parents.get(data.consumeInt(0, parents.size() - 1));
                            String tagName = data.consumeString(20);
                            if (data.consumeBoolean()) {
                                parent.appendElement(tagName);
                            } else {
                                parent.prependElement(tagName);
                            }
                        }
                        break;

                    case 5: // HTML appending/prepending
                        Elements containers = doc.select("*");
                        if (!containers.isEmpty()) {
                            Element container = containers.get(data.consumeInt(0, containers.size() - 1));
                            String htmlContent = data.consumeString(100);
                            if (data.consumeBoolean()) {
                                container.append(htmlContent);
                            } else {
                                container.prepend(htmlContent);
                            }
                        }
                        break;

                    case 6: // Element wrapping
                        Elements wrapElems = doc.select("*");
                        if (!wrapElems.isEmpty()) {
                            Element elem = wrapElems.get(data.consumeInt(0, wrapElems.size() - 1));
                            String wrapHtml = data.consumeString(50);
                            elem.wrap(wrapHtml);
                        }
                        break;

                    case 7: // Element removal
                        Elements removeElems = doc.select("*");
                        if (!removeElems.isEmpty()) {
                            Element elem = removeElems.get(data.consumeInt(0, removeElems.size() - 1));
                            if (data.consumeBoolean()) {
                                elem.remove();
                            } else {
                                elem.empty();
                            }
                        }
                        break;

                    case 8: // Element replacement
                        Elements replaceElems = doc.select("*");
                        if (!replaceElems.isEmpty()) {
                            Element elem = replaceElems.get(data.consumeInt(0, replaceElems.size() - 1));
                            String replacement = data.consumeString(100);
                            Element newElem = Jsoup.parse(replacement).body().child(0);
                            elem.replaceWith(newElem);
                        }
                        break;

                    case 9: // Element selection and traversal
                        String selector = data.consumeString(50);
                        Elements selected = doc.select(selector);
                        if (!selected.isEmpty()) {
                            Element elem = selected.first();
                            elem.parent();
                            elem.children();
                            elem.siblings();
                        }
                        break;

                    case 10: // Document structure access
                        doc.head();
                        doc.body();
                        doc.title();
                        if (data.consumeBoolean()) {
                            doc.title(data.consumeString(100));
                        }
                        break;

                    case 11: // Form element handling
                        Elements forms = doc.select("form");
                        if (!forms.isEmpty()) {
                            Element form = forms.first();
                            form.select("input, select, textarea");
                        }
                        break;

                    case 12: // Link and URL handling
                        Elements links = doc.select("a[href], link[href]");
                        for (Element link : links) {
                            link.attr("href");
                            link.attr("abs:href");
                            if (data.consumeBoolean()) break;
                        }
                        break;

                    case 13: // Text extraction with different methods
                        Elements textElems = doc.select("*");
                        if (!textElems.isEmpty()) {
                            Element elem = textElems.get(data.consumeInt(0, textElems.size() - 1));
                            elem.text();
                            elem.ownText();
                            elem.wholeText();
                        }
                        break;

                    case 14: // Data attribute handling
                        Elements dataElems = doc.select("*");
                        if (!dataElems.isEmpty()) {
                            Element elem = dataElems.get(data.consumeInt(0, dataElems.size() - 1));
                            String dataKey = data.consumeString(20);
                            elem.dataset().put(dataKey, data.consumeString(50));
                            elem.dataset().get(dataKey);
                        }
                        break;

                    case 15: // Output and serialization
                        doc.html();
                        doc.outerHtml();
                        doc.toString();
                        break;
                }
            }

        } catch (ValidationException | IndexOutOfBoundsException ignored) {
        }
    }
}