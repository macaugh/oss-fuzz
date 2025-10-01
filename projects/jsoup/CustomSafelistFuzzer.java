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
import org.jsoup.safety.Safelist;

public class CustomSafelistFuzzer {
    private static final String[] COMMON_TAGS = {
        "div", "span", "p", "br", "strong", "em", "b", "i", "u", "a", "img",
        "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "table", "tr", "td", "th",
        "blockquote", "code", "pre", "sup", "sub", "del", "ins", "mark", "small",
        "abbr", "cite", "dfn", "time", "address", "section", "article", "aside",
        "header", "footer", "nav", "main", "figure", "figcaption"
    };

    private static final String[] COMMON_ATTRIBUTES = {
        "class", "id", "title", "alt", "src", "href", "target", "rel", "type",
        "width", "height", "style", "data-value", "data-id", "role", "aria-label",
        "colspan", "rowspan", "scope", "lang", "dir", "tabindex"
    };

    private static final String[] PROTOCOLS = {
        "http", "https", "ftp", "mailto", "tel", "data", "javascript", "file"
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Start with a base safelist
            Safelist safelist = data.pickValue(new Safelist[]{
                Safelist.none(),
                Safelist.simpleText(),
                Safelist.basic(),
                Safelist.basicWithImages(),
                Safelist.relaxed()
            });

            // Customize the safelist with fuzzed data
            while (data.remainingBytes() > 30) {
                int operation = data.consumeInt(0, 7);

                switch (operation) {
                    case 0: // Add tags
                        String[] tagsToAdd = new String[data.consumeInt(1, 5)];
                        for (int i = 0; i < tagsToAdd.length && data.remainingBytes() > 10; i++) {
                            if (data.consumeBoolean()) {
                                tagsToAdd[i] = data.pickValue(COMMON_TAGS);
                            } else {
                                tagsToAdd[i] = data.consumeString(20);
                            }
                        }
                        safelist.addTags(tagsToAdd);
                        break;

                    case 1: // Remove tags
                        String[] tagsToRemove = new String[data.consumeInt(1, 3)];
                        for (int i = 0; i < tagsToRemove.length && data.remainingBytes() > 10; i++) {
                            tagsToRemove[i] = data.pickValue(COMMON_TAGS);
                        }
                        safelist.removeTags(tagsToRemove);
                        break;

                    case 2: // Add attributes
                        String tag = data.pickValue(COMMON_TAGS);
                        String[] attributes = new String[data.consumeInt(1, 4)];
                        for (int i = 0; i < attributes.length && data.remainingBytes() > 10; i++) {
                            if (data.consumeBoolean()) {
                                attributes[i] = data.pickValue(COMMON_ATTRIBUTES);
                            } else {
                                attributes[i] = data.consumeString(20);
                            }
                        }
                        safelist.addAttributes(tag, attributes);
                        break;

                    case 3: // Remove attributes
                        String tagForRemoval = data.pickValue(COMMON_TAGS);
                        String[] attrsToRemove = new String[data.consumeInt(1, 3)];
                        for (int i = 0; i < attrsToRemove.length && data.remainingBytes() > 10; i++) {
                            attrsToRemove[i] = data.pickValue(COMMON_ATTRIBUTES);
                        }
                        safelist.removeAttributes(tagForRemoval, attrsToRemove);
                        break;

                    case 4: // Add enforced attributes
                        String tagForEnforced = data.pickValue(COMMON_TAGS);
                        String enforcedAttr = data.pickValue(COMMON_ATTRIBUTES);
                        String enforcedValue = data.consumeString(50);
                        safelist.addEnforcedAttribute(tagForEnforced, enforcedAttr, enforcedValue);
                        break;

                    case 5: // Add protocols
                        String protocolTag = data.pickValue(new String[]{"a", "img", "link", "form"});
                        String protocolAttr = data.pickValue(new String[]{"href", "src", "action"});
                        String[] protocols = new String[data.consumeInt(1, 3)];
                        for (int i = 0; i < protocols.length && data.remainingBytes() > 5; i++) {
                            if (data.consumeBoolean()) {
                                protocols[i] = data.pickValue(PROTOCOLS);
                            } else {
                                protocols[i] = data.consumeString(15);
                            }
                        }
                        safelist.addProtocols(protocolTag, protocolAttr, protocols);
                        break;

                    case 6: // Remove protocols
                        String removeProtocolTag = data.pickValue(new String[]{"a", "img", "link"});
                        String removeProtocolAttr = data.pickValue(new String[]{"href", "src"});
                        String[] protocolsToRemove = new String[data.consumeInt(1, 2)];
                        for (int i = 0; i < protocolsToRemove.length && data.remainingBytes() > 5; i++) {
                            protocolsToRemove[i] = data.pickValue(PROTOCOLS);
                        }
                        safelist.removeProtocols(removeProtocolTag, removeProtocolAttr, protocolsToRemove);
                        break;

                    case 7: // Configure preserve relative links
                        safelist.preserveRelativeLinks(data.consumeBoolean());
                        break;
                }
            }

            // Test the customized safelist
            String html = data.consumeRemainingAsString();
            if (!html.isEmpty()) {
                // Test cleaning
                String baseUri = "https://example.com";
                Jsoup.clean(html, baseUri, safelist);

                // Test validation
                Jsoup.isValid(html, safelist);
            }

        } catch (ValidationException ignored) {
        } catch (IllegalArgumentException ignored) {
        }
    }
}