# Unused Symbols Analysis Report

**Date:** 2025-10-31  
**Repository:** ngtcp2/ngtcp2  
**Analysis Tool:** find-unused-symbols.py

## Summary

This report documents the findings from analyzing the ngtcp2 codebase for unused symbols (functions, macros, and enum values).

### Key Statistics

- **Total functions analyzed:** 877
- **Total macros analyzed:** 322
- **Total enum values analyzed:** 50
- **Public API symbols (excluded):** 203
- **Unused functions found:** 0
- **Unused macros found:** 0
- **Unused enum values found:** 1

## Findings

### Unused Enum Values (1)

The following enum value is defined but never used:

| Symbol | Location |
|--------|----------|
| `NETWORK_ERR_FATAL` | examples/network.h:51 |

#### Details: NETWORK_ERR_FATAL

- **Type:** Enum value
- **Defined in:** examples/network.h, line 51 (enum network_error)
- **Value:** -10
- **Context:** Part of the `network_error` enum which defines error codes for network operations

Other enum values in the same enum that ARE used:
- `NETWORK_ERR_OK` = 0
- `NETWORK_ERR_SEND_BLOCKED` = -11
- `NETWORK_ERR_CLOSE_WAIT` = -12
- `NETWORK_ERR_RETRY` = -13
- `NETWORK_ERR_DROP_CONN` = -14

**Recommendation:** If `NETWORK_ERR_FATAL` is not intended for future use, it could be removed to keep the codebase clean. Otherwise, it may be reserved for future error handling scenarios.

## Methodology

The analysis was performed using the `find-unused-symbols.py` script, which:

1. Scans all C/C++ source and header files in the lib/, crypto/, examples/, and tests/ directories
2. Extracts function definitions, macro definitions, and enum values using regular expressions
3. Excludes public API symbols (those defined in lib/includes/ngtcp2/ and crypto/includes/ngtcp2/)
4. Searches the entire codebase for usage of each symbol
5. Reports symbols that have zero usages (excluding their definition)

## Exclusions

The following were explicitly excluded from the unused symbol analysis:

- All symbols defined in public API headers:
  - lib/includes/ngtcp2/ngtcp2.h
  - lib/includes/ngtcp2/version.h
  - crypto/includes/ngtcp2/ngtcp2_crypto.h
  - crypto/includes/ngtcp2/ngtcp2_crypto_boringssl.h
  - crypto/includes/ngtcp2/ngtcp2_crypto_gnutls.h
  - crypto/includes/ngtcp2/ngtcp2_crypto_ossl.h
  - crypto/includes/ngtcp2/ngtcp2_crypto_picotls.h
  - crypto/includes/ngtcp2/ngtcp2_crypto_quictls.h
  - crypto/includes/ngtcp2/ngtcp2_crypto_wolfssl.h

These symbols are part of the public API and may be used by external applications.

## Conclusion

The ngtcp2 codebase is very clean with respect to unused symbols. Only one unused enum value was found, which may be intentionally reserved for future use. No unused functions or macros were detected, indicating good code hygiene and maintenance practices.

## Running the Analysis

To reproduce this analysis or run it on an updated codebase:

```bash
./find-unused-symbols.py
```

The script will output results to stdout. To save to a file:

```bash
./find-unused-symbols.py > report.txt
```
