#!/usr/bin/env python3

import subprocess
import re
import argparse
import sys
from collections import defaultdict

# Standard library functions to ignore by default
DEFAULT_IGNORE_PATTERNS = [
    r'^_?mem(set|cpy|move|cmp)',  # Memory operations
    r'^str(n?cpy|n?cat|len|cmp|str|tok|dup)',  # String operations
    r'^_?malloc',  # Memory allocation
    r'^_?free',  # Memory deallocation
    r'^_?realloc',  # Memory reallocation
    r'^_?calloc',  # Memory allocation
    r'^__.*_r$',  # Reentrant functions (like *memcpy*r)
    r'^__(assert|errno|exit|locale|malloc|retarget|sinit|sflush)',  # Various system functions
    r'^abort$',  # Abort function
    r'^raise$',  # Signal raising
    r'^_?exit$',  # Exit function
    r'^(f|s|v|vs)?printf',  # Printf variants
    r'^_?(get|set|close|open|read|write|lseek|isatty|fstat|stat|kill|getpid)',  # System calls
    r'^_?sbrk',  # Memory management
    r'lock_(acquire|release|init|close)',  # Lock operations
    r'^sys',  # System functions
]

def get_functions_and_sizes(elf_file):
    """
    Extract all functions and their sizes from the ELF file,
    using disassembly to calculate sizes for functions where the size attribute is missing
    """
    # First get the sizes using the traditional method (nm with --print-size)
    nm_output = subprocess.check_output(
        ["arm-none-eabi-nm", "--print-size", "--size-sort", "--radix=d", elf_file],
        universal_newlines=True
    )
    
    # Create a dictionary to store function names and their sizes
    functions = {}
    
    # Parse the output of nm
    for line in nm_output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[-2].lower() in ['t', 'w']:  # Text section symbols
            try:
                size = int(parts[-3])
                func_name = parts[-1]
                functions[func_name] = size
            except (ValueError, IndexError):
                continue
    
    # Run objdump to get disassembly for determining function boundaries
    objdump_output = subprocess.check_output(
        ["arm-none-eabi-objdump", "-d", "-M", "reg-names-std", elf_file],
        universal_newlines=True
    )
    
    # Regular expression to match function definition
    func_def_pattern = re.compile(r'^([0-9a-f]+) <([^>]+)>:')
    
    # Parse the disassembly output to find function boundaries
    lines = objdump_output.splitlines()
    func_addresses = []
    address_to_name = {}
    
    for line in lines:
        # Check if this line defines a new function
        func_match = func_def_pattern.match(line)
        if func_match:
            address = int(func_match.group(1), 16)
            func_name = func_match.group(2)
            func_addresses.append(address)
            address_to_name[address] = func_name
    
    # Sort addresses to determine function boundaries
    func_addresses.sort()
    
    # Calculate sizes based on function boundaries
    for i, addr in enumerate(func_addresses[:-1]):
        func_name = address_to_name[addr]
        next_addr = func_addresses[i + 1]
        
        # If function size is 0 or not defined, calculate it from boundaries
        if func_name in functions and functions[func_name] == 0:
            calculated_size = next_addr - addr
            functions[func_name] = calculated_size
        # If function not in the dictionary, add it
        elif func_name not in functions:
            calculated_size = next_addr - addr
            functions[func_name] = calculated_size
    
    # Special case for the last function in the list - use section boundaries if available
    if func_addresses:
        last_addr = func_addresses[-1]
        last_func = address_to_name[last_addr]
        
        # Try to get section end from readelf
        try:
            readelf_output = subprocess.check_output(
                ["arm-none-eabi-readelf", "-S", elf_file],
                universal_newlines=True
            )
            
            # Find the .text section end address
            text_section_match = re.search(r'\.text\s+\w+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)', readelf_output)
            if text_section_match:
                section_start = int(text_section_match.group(1), 16)
                section_size = int(text_section_match.group(2), 16)
                section_end = section_start + section_size
                
                # Only update if the current size is 0
                if last_func in functions and functions[last_func] == 0:
                    # Make sure we don't exceed section boundaries
                    if last_addr >= section_start and last_addr < section_end:
                        functions[last_func] = section_end - last_addr
                elif last_func not in functions:
                    if last_addr >= section_start and last_addr < section_end:
                        functions[last_func] = section_end - last_addr
        except subprocess.CalledProcessError:
            pass  # Ignore if readelf fails
    
    return functions

def get_function_addresses(elf_file):
    """
    Get start addresses for all functions for better matching
    """
    nm_output = subprocess.check_output(
        ["arm-none-eabi-nm", elf_file],
        universal_newlines=True
    )
    
    # Create a dictionary to map addresses to function names
    addr_to_func = {}
    func_to_addr = {}
    
    # Parse the output of nm
    for line in nm_output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[1].lower() in ['t', 'w']:  # Text section symbols
            try:
                addr = int(parts[0], 16)
                func_name = parts[2]
                addr_to_func[addr] = func_name
                func_to_addr[func_name] = addr
            except (ValueError, IndexError):
                continue
    
    return addr_to_func, func_to_addr

def get_call_graph(elf_file):
    """
    Generate a more accurate call graph from the ELF file
    """
    # Get function addresses for better matching
    addr_to_func, func_to_addr = get_function_addresses(elf_file)
    
    # Run objdump to get disassembly
    objdump_output = subprocess.check_output(
        ["arm-none-eabi-objdump", "-d", "-M", "reg-names-std", elf_file],
        universal_newlines=True
    )
    
    # Create a dictionary to store the call graph
    call_graph = defaultdict(set)
    current_function = None
    
    # Regular expressions to match function definition and various call instructions
    func_def_pattern = re.compile(r'^([0-9a-f]+) <([^>]+)>:')
    
    # Patterns for different types of calls in ARM assembly
    # BL (Branch with Link) - standard function call
    bl_pattern = re.compile(r'\s+[0-9a-f]+:\s+(?:[0-9a-f]+\s+)+bl\s+(?:0x)?([0-9a-f]+)')
    bl_symbol_pattern = re.compile(r'\s+[0-9a-f]+:\s+(?:[0-9a-f]+\s+)+bl\s+(?:0x)?[0-9a-f]+\s+<([^>]+)>')
    
    # BLX (Branch with Link and eXchange) - calls that might switch between ARM and Thumb mode
    blx_pattern = re.compile(r'\s+[0-9a-f]+:\s+(?:[0-9a-f]+\s+)+blx\s+(?:0x)?([0-9a-f]+)')
    blx_symbol_pattern = re.compile(r'\s+[0-9a-f]+:\s+(?:[0-9a-f]+\s+)+blx\s+(?:0x)?[0-9a-f]+\s+<([^>]+)>')
    blx_reg_pattern = re.compile(r'\s+[0-9a-f]+:\s+(?:[0-9a-f]+\s+)+blx\s+r\d+')
    
    # B (Branch) - sometimes used for tail calls
    b_symbol_pattern = re.compile(r'\s+[0-9a-f]+:\s+(?:[0-9a-f]+\s+)+b(?:\.w)?\s+(?:0x)?[0-9a-f]+\s+<([^>]+)>')
    
    # Parse the disassembly output to build the call graph
    lines = objdump_output.splitlines()
    for i, line in enumerate(lines):
        # Check if this line defines a new function
        func_match = func_def_pattern.match(line)
        if func_match:
            current_function = func_match.group(2)
            continue
            
        # Skip if we're not in a function
        if not current_function:
            continue
        
        # Check for various types of calls
        # 1. BL with symbol
        bl_symbol_match = bl_symbol_pattern.search(line)
        if bl_symbol_match:
            called_function = bl_symbol_match.group(1)
            if called_function != current_function:  # Avoid self-recursion
                call_graph[current_function].add(called_function)
            continue
        
        # 2. BL with address
        bl_match = bl_pattern.search(line)
        if bl_match:
            try:
                addr = int(bl_match.group(1), 16)
                if addr in addr_to_func:
                    called_function = addr_to_func[addr]
                    if called_function != current_function:
                        call_graph[current_function].add(called_function)
            except ValueError:
                pass
            continue
        
        # 3. BLX with symbol
        blx_symbol_match = blx_symbol_pattern.search(line)
        if blx_symbol_match:
            called_function = blx_symbol_match.group(1)
            if called_function != current_function:
                call_graph[current_function].add(called_function)
            continue
        
        # 4. BLX with address
        blx_match = blx_pattern.search(line)
        if blx_match:
            try:
                addr = int(blx_match.group(1), 16)
                if addr in addr_to_func:
                    called_function = addr_to_func[addr]
                    if called_function != current_function:
                        call_graph[current_function].add(called_function)
            except ValueError:
                pass
            continue
        
        # 5. B (tail call) with symbol - used for optimization
        b_symbol_match = b_symbol_pattern.search(line)
        if b_symbol_match:
            called_function = b_symbol_match.group(1)
            if called_function != current_function:
                call_graph[current_function].add(called_function)
            continue
    
    return call_graph

def should_ignore_function(func_name, ignore_patterns):
    """
    Check if a function should be ignored based on the ignore patterns
    """
    for pattern in ignore_patterns:
        if re.match(pattern, func_name):
            return True
    return False

def get_function_hierarchy(function_name, call_graph, ignore_patterns, visited=None, depth=0):
    """
    Build a hierarchical representation of function calls, excluding ignored functions
    """
    if visited is None:
        visited = set()
    
    # If we've already visited this function, skip it to avoid infinite recursion
    if function_name in visited:
        return []
    
    # Mark the function as visited
    visited.add(function_name)
    
    # Create a list to store the hierarchy
    hierarchy = []
    
    # Add the current function with its depth (don't ignore the root function)
    if depth == 0 or not should_ignore_function(function_name, ignore_patterns):
        hierarchy.append((function_name, depth))
    
    # Add all called functions recursively
    for called_function in sorted(call_graph.get(function_name, set())):
        # Skip ignored functions unless it's the root function
        if depth > 0 and should_ignore_function(called_function, ignore_patterns):
            continue
        
        # Add the called function and its children to the hierarchy
        sub_hierarchy = get_function_hierarchy(
            called_function, call_graph, ignore_patterns, visited, 
            depth + 1 if (depth == 0 or not should_ignore_function(function_name, ignore_patterns)) else depth
        )
        hierarchy.extend(sub_hierarchy)
    
    return hierarchy

def calculate_sizes_detailed(function_name, functions, call_graph, ignore_patterns):
    """
    Calculate the size of each function in the call hierarchy
    """
    # Get the function hierarchy
    hierarchy = get_function_hierarchy(function_name, call_graph, ignore_patterns)
    
    # Create a dictionary to store the size of each function
    sizes = {}
    for func, _ in hierarchy:
        if func in functions:
            sizes[func] = functions[func]
        else:
            sizes[func] = 0
    
    return hierarchy, sizes

def format_size_table(hierarchy, sizes, total_size):
    """
    Format the size information as a table
    """
    # Calculate the maximum length of function names for formatting
    max_name_length = max([len(func) for func, _ in hierarchy]) if hierarchy else 0
    max_name_length = max(max_name_length, len("FUNCTION"))
    
    # Create a header for the table
    header = f"{'FUNCTION':{max_name_length}} | {'SIZE (bytes)':<12} | {'% OF TOTAL':<12}"
    separator = "-" * len(header)
    
    # Create the rows of the table
    rows = []
    for func, depth in hierarchy:
        # Add indentation based on depth
        indented_name = "  " * depth + func
        
        # Get the size of the function
        size = sizes.get(func, 0)
        
        # Calculate the percentage of the total
        percentage = (size / total_size * 100) if total_size > 0 else 0
        
        # Format the row
        row = f"{indented_name:{max_name_length}} | {size:<12} | {percentage:.2f}%"
        rows.append(row)
    
    # Add a separator and total row
    rows.append(separator)
    rows.append(f"{'TOTAL':{max_name_length}} | {total_size:<12} | 100.00%")
    
    # Combine the header, separator, and rows
    table = [header, separator] + rows
    
    return "\n".join(table)

def calculate_total_size(hierarchy, sizes):
    """
    Calculate the total size from the hierarchy and sizes
    """
    total = 0
    for func, _ in hierarchy:
        total += sizes.get(func, 0)
    return total

def load_ignore_file(file_path):
    """
    Load ignore patterns from a file
    """
    patterns = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    patterns.append(line)
    except FileNotFoundError:
        print(f"Warning: Ignore file '{file_path}' not found.")
    
    return patterns

def get_function_code_size(elf_file, function_name, ignore_patterns, detailed=False):
    """
    Get the total code size of a function including all its subfunctions
    """
    try:
        # Verify the ELF file exists and is valid
        subprocess.check_output(["arm-none-eabi-readelf", "-h", elf_file], stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"Error: '{elf_file}' is not a valid ELF file or doesn't exist.")
        return None
    
    # Get all functions and their sizes
    functions = get_functions_and_sizes(elf_file)
    
    if function_name not in functions:
        print(f"Error: Function '{function_name}' not found in '{elf_file}'.")
        return None
    
    # Get the call graph with improved call detection
    call_graph = get_call_graph(elf_file)
    
    # Get detailed breakdown
    hierarchy, sizes = calculate_sizes_detailed(function_name, functions, call_graph, ignore_patterns)
    
    # Calculate the total size
    total_size = calculate_total_size(hierarchy, sizes)
    
    if detailed:
        # Format the table
        table = format_size_table(hierarchy, sizes, total_size)
        return total_size, table
    else:
        return total_size, None

def verify_toolchain():
    """
    Verify that the required ARM toolchain is installed
    """
    tools = ['arm-none-eabi-nm', 'arm-none-eabi-objdump', 'arm-none-eabi-readelf']
    missing = []
    
    for tool in tools:
        try:
            subprocess.check_output([tool, '--version'], stderr=subprocess.PIPE)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing.append(tool)
    
    if missing:
        print(f"Error: Required tools not found: {', '.join(missing)}")
        print("Please install the ARM embedded toolchain (arm-none-eabi)")
        return False
    
    return True

def main():
    parser = argparse.ArgumentParser(description="Calculate the code size of a function and its subfunctions in an ELF file")
    parser.add_argument("elf_file", help="Path to the ELF file")
    parser.add_argument("function_name", help="Name of the function to analyze")
    parser.add_argument("--detailed", "-d", action="store_true", help="Show detailed breakdown of function sizes")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show verbose output")
    parser.add_argument("--no-ignore-stdlib", action="store_true", help="Don't ignore standard library functions")
    parser.add_argument("--ignore-file", help="File containing additional patterns of functions to ignore")
    parser.add_argument("--show-ignore-patterns", action="store_true", help="Show the default ignore patterns and exit")
    
    args = parser.parse_args()
    
    # Show ignore patterns if requested
    if args.show_ignore_patterns:
        print("Default ignore patterns:")
        for pattern in DEFAULT_IGNORE_PATTERNS:
            print(f"  {pattern}")
        sys.exit(0)
    
    # Verify the toolchain is installed
    if not verify_toolchain():
        sys.exit(1)
    
    # Load ignore patterns
    ignore_patterns = []
    if not args.no_ignore_stdlib:
        ignore_patterns.extend(DEFAULT_IGNORE_PATTERNS)
    
    if args.ignore_file:
        ignore_patterns.extend(load_ignore_file(args.ignore_file))
    
    if args.verbose:
        print(f"Analyzing function '{args.function_name}' in file '{args.elf_file}'...")
        if ignore_patterns:
            print(f"Ignoring functions matching {len(ignore_patterns)} patterns")
    
    result = get_function_code_size(elf_file=args.elf_file, 
                                   function_name=args.function_name, 
                                   ignore_patterns=ignore_patterns,
                                   detailed=args.detailed)
    
    if result is not None:
        total_size, table = result
        
        if args.detailed and table:
            print("\nDETAILED SIZE BREAKDOWN:")
            print(table)
        else:
            print(f"Total code size of '{args.function_name}' (including subfunctions): {total_size} bytes")

if __name__ == "__main__":
    main()