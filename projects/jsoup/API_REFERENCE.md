# jsoup API Reference

Complete reference for all entry points and controllable settings in the jsoup library.

## Entry Points

### Primary Entry Points (`org.jsoup.Jsoup`)

#### Parsing HTML/XML
- `Jsoup.parse(String html)` - Parse HTML with empty base URI
- `Jsoup.parse(String html, String baseUri)` - Parse HTML with base URI for relative URL resolution
- `Jsoup.parse(String html, Parser parser)` - Parse with custom parser (e.g., XML parser)
- `Jsoup.parse(String html, String baseUri, Parser parser)` - Parse with base URI and custom parser

#### Parsing from Files
- `Jsoup.parse(File file)` - Parse file with auto-detected charset
- `Jsoup.parse(File file, String charsetName)` - Parse file with specified charset
- `Jsoup.parse(File file, String charsetName, String baseUri)` - Parse file with charset and base URI
- `Jsoup.parse(File file, String charsetName, String baseUri, Parser parser)` - Parse file with all options
- `Jsoup.parse(Path path)` - Parse Path with auto-detected charset
- `Jsoup.parse(Path path, String charsetName)` - Parse Path with specified charset
- `Jsoup.parse(Path path, String charsetName, String baseUri)` - Parse Path with charset and base URI
- `Jsoup.parse(Path path, String charsetName, String baseUri, Parser parser)` - Parse Path with all options

#### Parsing from Streams
- `Jsoup.parse(InputStream in, String charsetName, String baseUri)` - Parse InputStream
- `Jsoup.parse(InputStream in, String charsetName, String baseUri, Parser parser)` - Parse InputStream with custom parser

#### Parsing Fragments
- `Jsoup.parseBodyFragment(String bodyHtml)` - Parse HTML fragment as body content
- `Jsoup.parseBodyFragment(String bodyHtml, String baseUri)` - Parse fragment with base URI

#### HTTP Connections
- `Jsoup.connect(String url)` - Create HTTP connection to URL
- `Jsoup.newSession()` - Create reusable HTTP session
- `Jsoup.parse(URL url, int timeoutMillis)` - Direct URL parsing (legacy method)

#### HTML Sanitization
- `Jsoup.clean(String bodyHtml, Safelist safelist)` - Clean HTML with safelist
- `Jsoup.clean(String bodyHtml, String baseUri, Safelist safelist)` - Clean with base URI
- `Jsoup.clean(String bodyHtml, String baseUri, Safelist safelist, Document.OutputSettings outputSettings)` - Clean with output settings
- `Jsoup.isValid(String bodyHtml, Safelist safelist)` - Test if HTML passes safelist validation

## Connection Settings (`org.jsoup.Connection`)

### URL and Request Configuration
- `url(String url)` / `url(URL url)` - Set request URL
- `method(Method method)` - Set HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE)
- `timeout(int millis)` - Set connection and read timeout
- `maxBodySize(int bytes)` - Set maximum response body size
- `referrer(String referrer)` - Set HTTP referrer header
- `userAgent(String userAgent)` - Set user agent string
- `followRedirects(boolean followRedirects)` - Enable/disable redirect following

### Proxy Configuration
- `proxy(Proxy proxy)` - Set proxy
- `proxy(String host, int port)` - Set HTTP proxy by host/port

### SSL Configuration
- `sslSocketFactory(SSLSocketFactory sslSocketFactory)` - Set custom SSL socket factory

### Headers and Cookies
- `header(String name, String value)` - Set HTTP header
- `headers(Map<String,String> headers)` - Set multiple headers
- `cookie(String name, String value)` - Set cookie
- `cookies(Map<String, String> cookies)` - Set multiple cookies
- `cookieStore(CookieStore cookieStore)` - Set custom cookie store

### Request Data
- `data(String key, String value)` - Add form data
- `data(Collection<KeyVal> data)` - Set form data collection
- `data(Map<String, String> data)` - Set form data map
- `data(String... keyvals)` - Set form data from key-value pairs
- `data(String key, String filename, InputStream inputStream)` - Add file upload
- `data(String key, String filename, InputStream inputStream, String contentType)` - Add file upload with content type
- `requestBody(String body)` - Set raw request body

### Parser and Encoding
- `parser(Parser parser)` - Set custom parser for response
- `postDataCharset(String charset)` - Set form data encoding charset

### Error Handling
- `ignoreHttpErrors(boolean ignoreHttpErrors)` - Ignore HTTP error status codes
- `ignoreContentType(boolean ignoreContentType)` - Ignore unsupported content types

### System Properties
- `jsoup.useHttpClient` - Set to "false" to force HttpURLConnection instead of HttpClient on Java 11+

## Parser Settings (`org.jsoup.parser.Parser`)

### Parser Types
- `Parser.htmlParser()` - Create HTML parser (default)
- `Parser.xmlParser()` - Create XML parser for strict XML parsing

### Parser Configuration
- `setTrackErrors(int maxErrors)` - Enable error tracking with maximum error count
- `setTrackPosition(boolean trackPosition)` - Enable position tracking for errors
- `settings(ParseSettings settings)` - Set parsing settings (case sensitivity, etc.)
- `tagSet(TagSet tagSet)` - Set custom tag definitions

### ParseSettings Options
- Case sensitivity for tag names and attributes
- Attribute value handling
- Namespace preservation

## HTML Sanitization Settings

### Safelist Presets (`org.jsoup.safety.Safelist`)
- `Safelist.none()` - Remove all HTML, text only
- `Safelist.simpleText()` - Allow basic text formatting (b, em, i, strong, u)
- `Safelist.basic()` - Allow basic HTML tags (p, br, strong, b, em, i, etc.)
- `Safelist.basicWithImages()` - Basic + images (img with src/alt/title/width/height)
- `Safelist.relaxed()` - Relaxed HTML including lists, tables, links

### Safelist Customization
- `addTags(String... tags)` - Allow additional HTML tags
- `removeTags(String... tags)` - Remove allowed tags
- `addAttributes(String tag, String... attributes)` - Allow attributes for a tag
- `removeAttributes(String tag, String... attributes)` - Remove allowed attributes
- `addEnforcedAttribute(String tag, String attribute, String value)` - Force attribute value
- `removeEnforcedAttribute(String tag, String attribute)` - Remove enforced attribute
- `addProtocols(String tag, String attribute, String... protocols)` - Allow URL protocols
- `removeProtocols(String tag, String attribute, String... protocols)` - Remove allowed protocols
- `preserveRelativeLinks(boolean preserve)` - Keep relative URLs (requires base URI)

## Output Settings (`org.jsoup.nodes.Document.OutputSettings`)

### Syntax and Encoding
- `syntax(Syntax syntax)` - Set output syntax (HTML or XML)
- `charset(Charset charset)` / `charset(String charset)` - Set output character encoding
- `escapeMode(Entities.EscapeMode escapeMode)` - Set entity escaping mode:
  - `base` - Escape basic entities (&lt;, &gt;, &amp;, &quot;)
  - `extended` - Escape extended entities for better compatibility
  - `xhtml` - XHTML-compliant escaping

### Formatting
- `prettyPrint(boolean pretty)` - Enable/disable pretty-printing with indentation
- `outline(boolean outlineMode)` - Enable outline mode (block-level elements on new lines)
- `indentAmount(int indentAmount)` - Set number of spaces per indent level
- `maxPaddingWidth(int maxPaddingWidth)` - Set maximum padding width for alignment

## Document Manipulation

### Element Selection
- CSS selectors via `select(String cssQuery)`
- Traversal methods: `parent()`, `children()`, `siblings()`, etc.
- Find methods: `getElementById()`, `getElementsByTag()`, `getElementsByClass()`

### Content Modification
- Text content: `text()`, `text(String text)`
- HTML content: `html()`, `html(String html)`
- Attributes: `attr(String key)`, `attr(String key, String value)`, `removeAttr(String key)`
- Classes: `addClass(String className)`, `removeClass(String className)`, `toggleClass(String className)`

### Structure Modification
- Add elements: `append(String html)`, `prepend(String html)`, `appendElement(String tagName)`
- Remove elements: `remove()`, `empty()`
- Replace elements: `replaceWith(Node in)`, `wrap(String html)`

## Examples

### Basic Parsing
```java
Document doc = Jsoup.parse("<p>Hello world</p>");
Element p = doc.selectFirst("p");
System.out.println(p.text()); // "Hello world"
```

### HTTP Request with Settings
```java
Document doc = Jsoup.connect("https://example.com")
    .userAgent("Mozilla/5.0")
    .timeout(10000)
    .header("Accept", "text/html")
    .cookie("session", "abc123")
    .get();
```

### HTML Sanitization
```java
String unsafe = "<script>alert('xss')</script><p>Safe content</p>";
String safe = Jsoup.clean(unsafe, Safelist.basic());
// Result: "<p>Safe content</p>"
```

### Custom Output Settings
```java
Document doc = Jsoup.parse("<p>Content</p>");
doc.outputSettings()
    .prettyPrint(false)
    .charset("UTF-8")
    .escapeMode(Entities.EscapeMode.extended);
String html = doc.html();
```

### XML Parsing
```java
String xml = "<root><item>value</item></root>";
Document doc = Jsoup.parse(xml, "", Parser.xmlParser());
Element item = doc.selectFirst("item");
```

### Session Management
```java
Connection session = Jsoup.newSession()
    .timeout(20000)
    .userAgent("MyApp 1.0");

Document page1 = session.newRequest("https://site.com/login")
    .data("user", "name")
    .data("pass", "secret")
    .post();

Document page2 = session.newRequest("https://site.com/dashboard")
    .get(); // Cookies from login are preserved
```