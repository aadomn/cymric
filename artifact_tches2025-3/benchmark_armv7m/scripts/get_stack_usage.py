#!/usr/bin/env python3

import subprocess
import re
import argparse
import os
import sys
from collections import defaultdict

class ARMv7MStackAnalyzer:
    def __init__(self, elf_file, function_name, verbose=False):
        self.elf_file = elf_file
        self.function_name = function_name
        self.verbose = verbose
        self.call_graph = defaultdict(set)  # To track function call relationships
        self.stack_usage = {}  # Direct stack usage per function
        self.processed_functions = set()  # Used while building call graph
        self.recursive_functions = set()  # Track recursive functions
        
    def check_tools(self):
        """Check if required ARM tools are available."""
        required_tools = ['arm-none-eabi-nm', 'arm-none-eabi-objdump']
        
        for tool in required_tools:
            try:
                subprocess.run([tool, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            except FileNotFoundError:
                print(f"Error: Required tool '{tool}' not found in PATH")
                return False
        return True
    
    def get_disassembly(self, function_name):
        """Get disassembly of a function."""
        try:            
            cmd = 'arm-none-eabi-objdump -d {elf} | awk -v RS= \'/^[[:xdigit:]]+ <{func}>/\''.format(
    elf=self.elf_file, func=function_name)
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            if self.verbose:
                print(f"Warning: Error disassembling function {function_name}: {e}")
            return ""
    
    def get_direct_stack_usage(self, disassembly, function_name):
        """Calculate direct stack usage from disassembly."""
        stack_usage = 0
        lines = disassembly.splitlines()
        
        # For tracking stack pointer adjustments
        sp_adjustments = []
        
        # Patterns for stack allocation operations
        # 1. Different forms of SUB instructions that modify SP
        sub_patterns = [
            r'sub(?:\.w)?\s+sp,\s+(?:sp,\s+)?#(\d+)',  # sub sp, sp, #X or sub sp, #X
            r'subw\s+sp,\s+(?:sp,\s+)?#(\d+)',         # subw sp, sp, #X or subw sp, #X
            r'sub\.w\s+sp,\s+(?:sp,\s+)?#(\d+)',       # sub.w sp, sp, #X or sub.w sp, #X
        ]
        
        # 2. PUSH pseudo instructions
        push_pattern = r'push\s+{([^}]+)}'  # push {r0, r1, r2, ...}
        
        # 3. STMDB instructions (Store Multiple Decrement Before)
        stmdb_pattern = r'stmdb\s+sp!,\s+{([^}]+)}'  # stmdb sp!, {r0, r1, r2, ...}
        
        # 4. STR instructions that offset SP negatively
        str_pattern = r'str\s+\w+,\s+\[sp,\s+#-(\d+)\]'  # str rX, [sp, #-X]
        
        # Flag to detect function prologue
        found_prologue = False
        
        for line in lines:
            # Check for SUB SP instructions
            for pattern in sub_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    amount = int(match.group(1))
                    stack_usage += amount
                    sp_adjustments.append((line, amount))
                    found_prologue = True
                    break
            
            # Check for PUSH instructions
            match = re.search(push_pattern, line, re.IGNORECASE)
            if match:
                registers = match.group(1).split(',')
                # Each register is 4 bytes on 32-bit ARM
                amount = len(registers) * 4
                stack_usage += amount
                sp_adjustments.append((line, amount))
                found_prologue = True
            
            # Check for STMDB instructions (same as PUSH but different syntax)
            match = re.search(stmdb_pattern, line, re.IGNORECASE)
            if match:
                registers = match.group(1).split(',')
                # Each register is 4 bytes on 32-bit ARM
                amount = len(registers) * 4
                stack_usage += amount
                sp_adjustments.append((line, amount))
                found_prologue = True
            
            # Check for STR instructions that allocate stack space
            match = re.search(str_pattern, line, re.IGNORECASE)
            if match:
                amount = int(match.group(1))
                # Only count the maximum offset to avoid double counting
                # This is a heuristic - if we see stores at different offsets,
                # we assume the largest one represents the stack frame size
                if amount > stack_usage:
                    stack_usage = amount
                    sp_adjustments.append((line, amount))
        
        if self.verbose and sp_adjustments:
            print(f"\nStack adjustments in {function_name}:")
            for line, amount in sp_adjustments:
                print(f"  +{amount} bytes: {line.strip()}")
                
        return stack_usage
    
    def get_called_functions(self, disassembly):
        """Extract functions called from disassembly."""
        # Find all branch with and without link (bl/blx) instructions that call functions
        calls  = re.findall(r'bl(?:x)?\s+[0-9a-f]+\s+<([^>]+)>', disassembly)
        calls += re.findall(r'b(?:.w)?\s+[0-9a-f]+\s+<([^>]+)>', disassembly)

        # Functions to ignore
        ignored_functions = ['__assert_func']
        for ignored_func in ignored_functions:
            if ignored_func in calls:
                calls.remove(ignored_func)

        # Remove duplicates
        return set(calls)  
    
    def build_call_graph(self, function_name, call_stack=None):
        """Build a call graph starting from the specified function."""
        if call_stack is None:
            call_stack = []
            
        # Check for recursion
        if function_name in call_stack:
            self.recursive_functions.add(function_name)
            return
            
        # Check if already processed to avoid redundant work
        if function_name in self.processed_functions:
            return
            
        # Mark as processed
        self.processed_functions.add(function_name)
        
        disassembly = self.get_disassembly(function_name)
        stack_usage = self.get_direct_stack_usage(disassembly, function_name)
        self.stack_usage[function_name] = stack_usage
        
        if self.verbose:
            print(f"{'  ' * len(call_stack)}Function {function_name} uses {stack_usage} bytes of stack directly")
        
        # Find called functions
        called_functions = self.get_called_functions(disassembly)
        for called_func in called_functions:
            self.call_graph[function_name].add(called_func)
            
        # Recursively process called functions
        new_call_stack = call_stack + [function_name]
        for called_func in called_functions:
            self.build_call_graph(called_func, new_call_stack)

    def find_max_stack_path(self, function_name, visited=None, depth=0):
        """Find the path with maximum stack usage from this function."""
        if visited is None:
            visited = set()
            
        # Handle recursion and cycles
        if function_name in visited:
            if self.verbose and depth > 0:
                print(f"{'  ' * depth}Detected recursive call to {function_name}, stopping recursion")
            return 0, []
            
        # Mark as visited for this path
        visited.add(function_name)
        
        # Get direct stack usage for this function
        direct_usage = self.stack_usage.get(function_name, 0)
        
        # Base case: no called functions
        if not self.call_graph[function_name]:
            return direct_usage, [function_name]
            
        # Find the call path with maximum stack usage
        max_child_usage = 0
        max_child_path = []
        
        for called_func in self.call_graph[function_name]:
            if self.verbose and depth > 0:
                print(f"{'  ' * depth}Analyzing path: {function_name} -> {called_func}")
                
            child_usage, child_path = self.find_max_stack_path(called_func, visited.copy(), depth + 1)
            total_path_usage = child_usage
            
            if total_path_usage > max_child_usage:
                max_child_usage = total_path_usage
                max_child_path = child_path
                
        # Total usage is direct usage plus maximum of called functions
        return direct_usage + max_child_usage, [function_name] + max_child_path
    
    def get_stack_usage(self):
        """Perform the complete stack analysis."""
        print("========== ARMv7M Stack Usage Analyzer ==========")
        print(f"Analyzing stack usage for function: {self.function_name}")
        print(f"ELF file: {self.elf_file}")
        print("================================================")
        
        # Check if required tools are available
        if not self.check_tools():
            return 0
        
        # Build the call graph
        print("Building function call graph...")
        self.build_call_graph(self.function_name)
        
        if self.verbose:
            print("\nCall Graph:")
            for func, callees in sorted(self.call_graph.items()):
                if callees:
                    print(f"{func} calls: {', '.join(sorted(callees))}")
        
        # Find the path with maximum stack usage
        print("\nCalculating maximum stack usage path...")
        total_stack, max_path = self.find_max_stack_path(self.function_name)
        
        # Get direct stack usage of the main function
        direct_stack = self.stack_usage.get(self.function_name, 0)
        
        # Print summary
        print("================================================")
        print(f"Stack Usage Summary for {self.function_name}:")
        print(f"  Direct stack usage:     {direct_stack} bytes")
        print(f"  Including subfunctions: {total_stack} bytes (maximum call path)")
        
        if self.recursive_functions:
            print(f"  Warning: Detected recursive function(s): {', '.join(sorted(self.recursive_functions))}")
            print("  Note: For recursive functions, reported stack usage is for a single call path")
        
        print("\nMaximum stack consumption path:")
        stack_so_far = 0
        for i, func in enumerate(max_path):
            usage = self.stack_usage.get(func, 0)
            stack_so_far += usage
            
            if i < len(max_path) - 1:  # Not the last function
                indent = "  " * i
                print(f"{indent}↓ {func} (+{usage} bytes) → running total: {stack_so_far} bytes")
            else:  # Last function
                indent = "  " * i
                print(f"{indent}→ {func} (+{usage} bytes) → final total: {stack_so_far} bytes")
        
        print("================================================")
        return stack_so_far

def main():
    parser = argparse.ArgumentParser(description='Analyze stack usage for STM32 functions')
    parser.add_argument("elf_file", help="Path to the ELF file")
    parser.add_argument("function_name", help="Name of the function to analyze")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Check if the ELF file exists
    if not os.path.isfile(args.elf_file):
        print(f"Error: ELF file '{args.elf_file}' not found")
        return 0
    
    analyzer = ARMv7MStackAnalyzer(args.elf_file, args.function_name, args.verbose)
    stack = analyzer.get_stack_usage()

    return stack
    
if __name__ == "__main__":
    sys.exit(main())