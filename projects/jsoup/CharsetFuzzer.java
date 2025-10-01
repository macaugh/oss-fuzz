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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.UnsupportedCharsetException;

public class CharsetFuzzer {
    private static final String[] CHARSETS = {
        "UTF-8", "UTF-16", "UTF-16BE", "UTF-16LE", "UTF-32",
        "ISO-8859-1", "ASCII", "windows-1252", "GBK", "Big5",
        "Shift_JIS", "EUC-JP", "EUC-KR", "KOI8-R"
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            String charset = data.pickValue(CHARSETS);
            String baseUri = data.consumeString(50);
            byte[] htmlBytes = data.consumeRemainingAsBytes();

            // Test different charset parsing methods
            switch (data.consumeInt(0, 1)) {
                case 0:
                    // Test InputStream parsing with charset
                    ByteArrayInputStream stream = new ByteArrayInputStream(htmlBytes);
                    Jsoup.parse(stream, charset, baseUri);
                    break;
                case 1:
                    // Test InputStream parsing with charset and parser
                    ByteArrayInputStream stream2 = new ByteArrayInputStream(htmlBytes);
                    Jsoup.parse(stream2, charset, baseUri, org.jsoup.parser.Parser.htmlParser());
                    break;
            }
        } catch (ValidationException | IOException ignored) {
        }
    }
}
