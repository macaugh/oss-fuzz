# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OSS-Fuzz is Google's continuous fuzzing service for open source software. It uses Docker-based containerization to build and fuzz projects with multiple fuzzing engines (libFuzzer, AFL++, Honggfuzz) and sanitizers (AddressSanitizer, MemorySanitizer, UndefinedBehaviorSanitizer). The service supports C/C++, Rust, Go, Python, Java/JVM, JavaScript, Swift, and Ruby projects.

## Architecture

OSS-Fuzz operates in three phases:
1. **Build Phase**: Projects built with fuzzing instrumentation in Docker containers
2. **Fuzzing Phase**: Continuous execution on Google's ClusterFuzz infrastructure
3. **Reporting Phase**: Automated bug filing and tracking

### Key Directories

- **`/infra/`**: Core infrastructure, CLI tools, base Docker images, CI/CD
- **`/projects/`**: Individual project configurations (1000+ projects)
- **`/docs/`**: Integration guides and documentation
- **`/build/`**: Local build artifacts and outputs

### Project Structure (each `/projects/<name>/`)

Required files:
- `project.yaml` - Project metadata and configuration
- `Dockerfile` - Build environment setup
- `build.sh` - Compiles fuzz targets with instrumentation

Optional files:
- Fuzz target source files (`.c`, `.cpp`, `.java`, etc.)
- `run_tests.sh` - Project-specific tests

## Common Commands

All commands use `infra/helper.py` as the main CLI interface:

### Project Development
```bash
# Generate new project skeleton
python infra/helper.py generate <project_name>

# Build project Docker image
python infra/helper.py build_image <project_name>

# Compile fuzz targets
python infra/helper.py build_fuzzers <project_name>

# Validate fuzzers work correctly
python infra/helper.py check_build <project_name>

# Interactive debugging shell
python infra/helper.py shell <project_name>
```

### Fuzzing Operations
```bash
# Run specific fuzzer locally
python infra/helper.py run_fuzzer <project_name> <fuzzer_name>

# Generate code coverage report
python infra/helper.py coverage <project_name>

# Reproduce crash from testcase
python infra/helper.py reproduce <project_name> <fuzzer_name> <testcase>

# Download public corpora
python infra/helper.py download_corpora <project_name>

# Run introspector analysis
python infra/helper.py introspector <project_name>
```

### Base Images
```bash
# Pull latest base images
python infra/helper.py pull_images

# Build all base images (time-intensive)
infra/base-images/all.sh
```

## Docker Architecture

Base image hierarchy:
```
base-image (Ubuntu + tools)
├── base-clang (LLVM toolchain)
│   ├── base-builder (fuzzing tools)
│   │   ├── base-builder-go
│   │   ├── base-builder-python
│   │   ├── base-builder-jvm
│   │   └── [other language variants]
│   └── base-runner (execution environment)
```

### Critical Environment Variables
- `SANITIZER`: address/memory/undefined/coverage
- `FUZZING_ENGINE`: libfuzzer/afl/honggfuzz
- `LIB_FUZZING_ENGINE`: Engine library path for linking
- `SRC`, `OUT`, `WORK`: Standard build directories
- `CC`, `CXX`: Instrumented compilers

## Build Process

1. **Image Build**: Creates project-specific Docker environment
2. **Fuzzer Compilation**: `build.sh` compiles targets with `$LIB_FUZZING_ENGINE`
3. **Output**: Fuzz binaries placed in `$OUT` directory
4. **Validation**: `check_build` ensures targets execute properly

### Build Script Requirements (`build.sh`)
- Use `$CC`/`$CXX` compilers with fuzzing flags
- Link targets with `$LIB_FUZZING_ENGINE`
- Output all binaries to `$OUT` directory
- Include seed corpora and dictionaries as needed

## Project Configuration (`project.yaml`)

### Essential Fields
```yaml
homepage: https://project-website.com
language: c++  # or go, python, jvm, rust, javascript, swift, ruby
primary_contact: maintainer@example.com
main_repo: https://github.com/project/repo
```

### Common Options
```yaml
sanitizers: [address, memory, undefined]
fuzzing_engines: [libfuzzer, afl, honggfuzz]
architectures: [x86_64, i386]
auto_ccs: [additional@contacts.com]
file_github_issue: true  # Auto-file bugs on GitHub
```

## Language-Specific Patterns

- **C/C++**: Direct compiler integration, use `$CC`/`$CXX`
- **Go**: Use `compile_go_fuzzer` wrapper function
- **Python**: Integrate with `atheris` fuzzing framework
- **Java/JVM**: Use `jazzer` for JVM languages, output `.jar` files
- **JavaScript**: Node.js fuzzing with custom harnesses
- **Rust**: `cargo fuzz` integration patterns
- **Swift**: Specialized Swift toolchain support

## Testing and Validation

### Local Testing Workflow
1. `build_image` - Verify Docker setup
2. `build_fuzzers` - Check compilation
3. `check_build` - Validate fuzzers execute
4. `run_fuzzer` - Test fuzzing behavior
5. `coverage` - Assess effectiveness

### CI/CD Validation
- `infra/presubmit.py` validates project configurations
- Automated build testing via GitHub Actions
- Integration with ClusterFuzz for continuous execution

## Debugging and Analysis

### Crash Investigation
- Use `reproduce` command with crash testcases
- `shell` command for interactive debugging
- Check sanitizer reports for detailed error information

### Coverage Analysis
- `coverage` command generates HTML reports
- Focus on increasing line/function coverage in fuzz targets
- Use `introspector` for deeper code reachability analysis

## ClusterFuzzLite Integration

For CI/CD integration via `.clusterfuzzlite/`:
- `project.yaml` - CIFuzzLite configuration
- Batch fuzzing for regression testing
- GitHub Actions integration available