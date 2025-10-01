# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
jsoup is a Java HTML parser library that provides DOM manipulation, CSS selectors, and HTML sanitization capabilities. It implements the WHATWG HTML5 specification and handles malformed HTML gracefully.

## Development Commands

### Build and Test
- **Build project**: `mvn compile`
- **Run all tests**: `mvn test`
- **Run integration tests**: `mvn verify` or `mvn test -Pfailsafe`
- **Run specific test class**: `mvn test -Dtest=ClassNameTest`
- **Package JAR**: `mvn package`
- **Clean build**: `mvn clean compile`

### Code Quality
- **API compatibility check**: `mvn japicmp:cmp` (compares against previous version)
- **Generate Javadoc**: `mvn javadoc:javadoc`

### Multi-Release JAR
This project builds a multi-release JAR supporting Java 8+ with Java 11+ optimizations:
- Java 11+ features are in `src/main/java11/`
- Java 11+ tests are in `src/test/java11/`
- Build automatically handles multi-release compilation when run on JDK 11+

## Architecture

### Core Packages
- **`org.jsoup`**: Main entry point with `Jsoup` class providing static factory methods
- **`org.jsoup.nodes`**: DOM tree implementation (`Document`, `Element`, `Node`, `TextNode`, etc.)
- **`org.jsoup.parser`**: HTML/XML parsing engine with tokenizer and tree builder
- **`org.jsoup.select`**: CSS selector engine and `Elements` collection
- **`org.jsoup.safety`**: HTML sanitization with `Cleaner` and `Safelist`
- **`org.jsoup.helper`**: Utility classes including HTTP connection handling
- **`org.jsoup.internal`**: Internal implementation details (not public API)
- **`org.jsoup.examples`**: Example usage code

### Key Design Patterns
- **Factory Pattern**: `Jsoup` class provides static factory methods for parsing
- **Builder Pattern**: `Connection` interface for configuring HTTP requests
- **Visitor Pattern**: Node traversal and manipulation
- **Fluent Interface**: Method chaining for DOM manipulation and CSS selection

### HTML Processing Flow
1. **Input** → **Tokenizer** → **Tree Builder** → **DOM Tree**
2. **DOM manipulation** via CSS selectors or traversal methods
3. **Output** as cleaned/formatted HTML

### Multi-Release JAR Structure
- Base classes compiled for Java 8 compatibility
- Java 11+ optimizations in `META-INF/versions/11/`
- Automatic compatibility checking with Animal Sniffer plugin

## Development Notes

### Code Style
- Follows standard Java conventions
- Uses `@Nullable` annotations from jspecify
- Package-private classes for internal implementation

### Testing Strategy
- Unit tests in `src/test/java/`
- Integration tests with embedded Jetty server
- Multi-version compatibility tests in `src/test/java11/`
- Tests run with reduced stack size (`-Xss640k`) to catch stack overflow issues

### Dependencies
- **Runtime**: Zero dependencies (optional re2j for linear-time regex)
- **Test**: JUnit Jupiter, Gson, Jetty
- **Build**: jspecify annotations (compile-time only)

### Compatibility
- **Java**: 8+ (with Android 21+ support via desugaring)
- **Multi-release**: Optimized versions for Java 11+
- **API stability**: Maintained with japicmp compatibility checking