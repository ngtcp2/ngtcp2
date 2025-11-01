# Find Unused Symbols

This script analyzes the ngtcp2 codebase to identify unused functions, macros, and enum values.

## Purpose

The `find-unused-symbols.py` script helps maintain code quality by identifying:
- **Functions** that are defined but never called
- **Macros** that are defined but never used
- **Enum values** that are defined but never referenced

Public API symbols (those defined in `lib/includes/ngtcp2/` and `crypto/includes/ngtcp2/`) are excluded from the analysis, as these are part of the public interface and may be used by external code.

## Usage

```bash
./find-unused-symbols.py [path_to_ngtcp2_root]
```

If no path is provided, the current directory is used.

## Example Output

```
Analyzing ngtcp2 repository at: /path/to/ngtcp2

Analyzing files...
Found 877 function definitions
Found 322 macro definitions
Found 50 enum value definitions
Found 203 public symbols (excluded)

Searching for unused symbols...
  Checking functions: 100/877
  ...

================================================================================
UNUSED SYMBOLS REPORT
================================================================================

Note: Public API symbols (defined in lib/includes/ngtcp2/ and
crypto/includes/ngtcp2/) are excluded from this analysis.

No unused functions found.

No unused macros found.

UNUSED ENUM VALUES (1):
--------------------------------------------------------------------------------
  NETWORK_ERR_FATAL                        examples/network.h:51

================================================================================
SUMMARY: 0 unused functions, 0 unused macros, 1 unused enums
================================================================================
```

## How It Works

1. **File Discovery**: The script scans the `lib/`, `crypto/`, `examples/`, and `tests/` directories for C/C++ source and header files.

2. **Symbol Extraction**: For each file, it extracts:
   - Function definitions (looking for patterns like `type name(...) {`)
   - Macro definitions (looking for `#define NAME`)
   - Enum values (extracting identifiers from `enum { ... }` blocks)

3. **Public API Filtering**: Symbols defined in public headers (`lib/includes/ngtcp2/` and `crypto/includes/ngtcp2/`) are marked as public and excluded from the unused symbol check.

4. **Usage Detection**: For each non-public symbol, the script searches the entire codebase for references to that symbol (excluding the line where it's defined).

5. **Reporting**: Symbols with zero usages are reported as unused.

## Limitations

- The script uses regular expressions for parsing, which may not catch all edge cases in complex C/C++ code.
- It performs a simple text-based search for usage, which may produce false positives if symbols are used in ways the regex doesn't detect (e.g., through string concatenation macros).
- Comments are stripped before analysis to avoid false matches, but this is done with a simple regex that may not handle all comment styles perfectly.
- The script does not perform deep semantic analysis or follow #include directives.

## Requirements

- Python 3.6 or later
- No external dependencies (uses only Python standard library)
