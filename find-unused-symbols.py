#!/usr/bin/env python3
"""
Script to find unused functions, macros, and enums in ngtcp2 codebase.

This script analyzes C/C++ source files to identify symbols (functions, macros,
and enum values) that are defined but never used. Public API symbols defined in
lib/includes/ngtcp2/ and crypto/includes/ngtcp2/ are excluded from the analysis.

Usage:
    ./find-unused-symbols.py [path_to_ngtcp2_root]

If no path is provided, the current directory is used.
"""

import os
import re
import sys
from pathlib import Path
from collections import defaultdict
from typing import Set, Dict, List, Tuple

# Directories containing public API headers (should be excluded from unused analysis)
PUBLIC_API_DIRS = [
    'lib/includes/ngtcp2',
    'crypto/includes/ngtcp2'
]

# Directories to scan for source files
SCAN_DIRS = [
    'lib',
    'crypto',
    'examples',
    'tests'
]

class SymbolAnalyzer:
    """Analyzes C/C++ code to find unused symbols."""
    
    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        # Maps symbol name to list of (file, line) tuples where it's defined
        # For enums: (file, start_line, end_line)
        self.functions: Dict[str, List[Tuple[Path, int]]] = defaultdict(list)
        self.macros: Dict[str, List[Tuple[Path, int]]] = defaultdict(list)
        self.enums: Dict[str, List[Tuple[Path, int, int]]] = defaultdict(list)
        self.public_symbols: Set[str] = set()
        self.file_contents: Dict[Path, str] = {}
        
    def is_public_header(self, file_path: Path) -> bool:
        """Check if a file is a public API header."""
        try:
            relative_path = str(file_path.relative_to(self.base_path))
            for public_dir in PUBLIC_API_DIRS:
                if relative_path.startswith(public_dir):
                    return True
        except ValueError:
            pass
        return False
    
    def get_c_files(self) -> List[Path]:
        """Get all C/C++ and header files to analyze."""
        files = []
        for scan_dir in SCAN_DIRS:
            dir_path = self.base_path / scan_dir
            if dir_path.exists():
                files.extend(dir_path.rglob('*.c'))
                files.extend(dir_path.rglob('*.cc'))
                files.extend(dir_path.rglob('*.cpp'))
                files.extend(dir_path.rglob('*.h'))
                files.extend(dir_path.rglob('*.hh'))
        return files
    
    def extract_functions(self, content: str, file_path: Path, is_public: bool):
        """Extract function definitions from C/C++ code."""
        # Remove comments first to avoid false matches
        content_no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content_no_comments = re.sub(r'//.*', '', content_no_comments)
        
        lines = content_no_comments.split('\n')
        for i, line in enumerate(lines, 1):
            # Look for function definitions
            # Must start at beginning of line (possibly with qualifiers)
            # Match: [static] [inline] [extern] [const] type name(...) { or ;
            # Exclude lines that start with whitespace (likely inside a function)
            # Exclude lines with 'return', 'if', 'while', etc.
            stripped = line.lstrip()
            if not stripped or stripped.startswith('*'):
                continue
            
            # Skip lines that look like function calls (contain 'return' or have leading whitespace)
            if 'return ' in line or '  ' in line.lstrip()[:2]:
                continue
                
            match = re.match(r'^(?:static\s+)?(?:inline\s+)?(?:extern\s+)?(?:const\s+)?(?:\w+(?:\s*\*)*\s+)(\w+)\s*\([^)]*\)\s*[{;]', line)
            if match:
                func_name = match.group(1)
                # Skip common C keywords and operators
                if func_name not in ['if', 'for', 'while', 'switch', 'return', 'sizeof', 'typedef', 'assert']:
                    if is_public:
                        self.public_symbols.add(func_name)
                    else:
                        self.functions[func_name].append((file_path, i))
    
    def extract_macros(self, content: str, file_path: Path, is_public: bool):
        """Extract macro definitions from C/C++ code."""
        # Match #define macros (both function-like and object-like)
        macro_pattern = r'^\s*#\s*define\s+(\w+)'
        
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            match = re.match(macro_pattern, line)
            if match:
                macro_name = match.group(1)
                # Skip include guards (usually end with _H, _H_, or _HPP)
                if not (macro_name.endswith('_H') or macro_name.endswith('_H_') or macro_name.endswith('_HPP')):
                    if is_public:
                        self.public_symbols.add(macro_name)
                    else:
                        self.macros[macro_name].append((file_path, i))
    
    def extract_enums(self, content: str, file_path: Path, is_public: bool):
        """Extract enum values from C/C++ code."""
        # Match enum definitions
        # Pattern matches: enum name { ... } or typedef enum { ... }
        enum_pattern = r'(?:typedef\s+)?enum\s+(?:\w+\s*)?\{([^}]+)\}'
        
        for match in re.finditer(enum_pattern, content, re.DOTALL):
            enum_content = match.group(1)
            # Calculate the start and end line numbers of the entire enum block
            start_line = content[:match.start()].count('\n') + 1
            end_line = content[:match.end()].count('\n') + 1
            
            # Extract individual enum values (identifier at start of line or after comma)
            # Match: IDENTIFIER or IDENTIFIER = value
            enum_values = re.findall(r'(?:^|,)\s*(\w+)\s*(?:=|,|$)', enum_content, re.MULTILINE)
            for enum_value in enum_values:
                # Skip if it starts with a digit (it's probably a hex/octal value)
                if enum_value and not enum_value[0].isdigit():
                    if is_public:
                        self.public_symbols.add(enum_value)
                    else:
                        # Store the entire enum block range, not just the start
                        self.enums[enum_value].append((file_path, start_line, end_line))
    
    def analyze_files(self):
        """Analyze all C/C++ files and extract symbols."""
        print("Analyzing files...")
        files = self.get_c_files()
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    self.file_contents[file_path] = content
                    
                is_public = self.is_public_header(file_path)
                
                self.extract_functions(content, file_path, is_public)
                self.extract_macros(content, file_path, is_public)
                self.extract_enums(content, file_path, is_public)
                
            except Exception as e:
                print(f"Error reading {file_path}: {e}", file=sys.stderr)
        
        print(f"Found {len(self.functions)} function definitions")
        print(f"Found {len(self.macros)} macro definitions")
        print(f"Found {len(self.enums)} enum value definitions")
        print(f"Found {len(self.public_symbols)} public symbols (excluded)")
    
    def find_symbol_usage(self, symbol: str, def_file: Path, def_start_line: int, def_end_line: int = None) -> int:
        """Count how many times a symbol is used in the codebase (excluding its definition)."""
        usage_count = 0
        pattern = r'\b' + re.escape(symbol) + r'\b'
        
        if def_end_line is None:
            def_end_line = def_start_line
        
        for file_path, content in self.file_contents.items():
            lines = content.split('\n')
            for i, line in enumerate(lines, 1):
                # Skip the definition lines
                if file_path == def_file and def_start_line <= i <= def_end_line:
                    continue
                
                # Check if this line contains the symbol
                if re.search(pattern, line):
                    usage_count += 1
        
        return usage_count
    
    def find_unused_symbols(self) -> Tuple[List, List, List]:
        """Find unused functions, macros, and enums."""
        print("\nSearching for unused symbols...")
        
        unused_functions = []
        unused_macros = []
        unused_enums = []
        
        # Check functions
        total = len(self.functions)
        for idx, (func_name, locations) in enumerate(self.functions.items(), 1):
            if idx % 100 == 0:
                print(f"  Checking functions: {idx}/{total}")
            if func_name not in self.public_symbols:
                for file_path, line_num in locations:
                    usage_count = self.find_symbol_usage(func_name, file_path, line_num)
                    if usage_count == 0:
                        unused_functions.append((func_name, [(file_path, line_num)]))
                        break  # Only report once per symbol
        
        # Check macros
        total = len(self.macros)
        for idx, (macro_name, locations) in enumerate(self.macros.items(), 1):
            if idx % 100 == 0:
                print(f"  Checking macros: {idx}/{total}")
            if macro_name not in self.public_symbols:
                for file_path, line_num in locations:
                    usage_count = self.find_symbol_usage(macro_name, file_path, line_num)
                    if usage_count == 0:
                        unused_macros.append((macro_name, [(file_path, line_num)]))
                        break  # Only report once per symbol
        
        # Check enums
        total = len(self.enums)
        for idx, (enum_name, locations) in enumerate(self.enums.items(), 1):
            if enum_name not in self.public_symbols:
                for file_path, start_line, end_line in locations:
                    usage_count = self.find_symbol_usage(enum_name, file_path, start_line, end_line)
                    if usage_count == 0:
                        unused_enums.append((enum_name, [(file_path, start_line)]))
                        break  # Only report once per symbol
        
        return unused_functions, unused_macros, unused_enums
    
    def print_report(self, unused_functions, unused_macros, unused_enums):
        """Print a report of unused symbols."""
        print("\n" + "=" * 80)
        print("UNUSED SYMBOLS REPORT")
        print("=" * 80)
        print("\nNote: Public API symbols (defined in lib/includes/ngtcp2/ and")
        print("crypto/includes/ngtcp2/) are excluded from this analysis.")
        
        if unused_functions:
            print(f"\nUNUSED FUNCTIONS ({len(unused_functions)}):")
            print("-" * 80)
            for func_name, locations in sorted(unused_functions):
                for file_path, line_num in locations:
                    rel_path = file_path.relative_to(self.base_path)
                    print(f"  {func_name:40s} {rel_path}:{line_num}")
        else:
            print("\nNo unused functions found.")
        
        if unused_macros:
            print(f"\nUNUSED MACROS ({len(unused_macros)}):")
            print("-" * 80)
            for macro_name, locations in sorted(unused_macros):
                for file_path, line_num in locations:
                    rel_path = file_path.relative_to(self.base_path)
                    print(f"  {macro_name:40s} {rel_path}:{line_num}")
        else:
            print("\nNo unused macros found.")
        
        if unused_enums:
            print(f"\nUNUSED ENUM VALUES ({len(unused_enums)}):")
            print("-" * 80)
            for enum_name, locations in sorted(unused_enums):
                for file_path, line_num in locations:
                    rel_path = file_path.relative_to(self.base_path)
                    print(f"  {enum_name:40s} {rel_path}:{line_num}")
        else:
            print("\nNo unused enum values found.")
        
        print("\n" + "=" * 80)
        print(f"SUMMARY: {len(unused_functions)} unused functions, "
              f"{len(unused_macros)} unused macros, {len(unused_enums)} unused enums")
        print("=" * 80)


def main():
    """Main entry point for the script."""
    if len(sys.argv) > 1:
        base_path = sys.argv[1]
    else:
        base_path = os.getcwd()
    
    if not Path(base_path).exists():
        print(f"Error: Path '{base_path}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    print(f"Analyzing ngtcp2 repository at: {base_path}")
    print()
    
    analyzer = SymbolAnalyzer(base_path)
    analyzer.analyze_files()
    
    unused_functions, unused_macros, unused_enums = analyzer.find_unused_symbols()
    analyzer.print_report(unused_functions, unused_macros, unused_enums)


if __name__ == '__main__':
    main()
