import subprocess
import argparse
import json
import re

def get_func_size(elf_file, func_name):
    result = subprocess.run([
        "python3", "get_size.py", elf_file, func_name
    ], capture_output=True, text=True)
    return int(re.search(r'(\d+)\s+bytes', result.stdout).group(1))

def get_stack_usage(elf_file, func_name):
    result = subprocess.run([
        "python3", "get_stack_usage.py", elf_file, func_name
    ],capture_output = True, text=True)
    return int(re.search(r'final total:+\s+(\d+)\s+bytes', result.stdout).group(1))

def analyze_functions(elf_file, functions):
    results = []
    for f in functions:
        # because cymric implementations are cipher-agnostic it requirse some
        # adjusments
        if (f[0][:6] == 'cymric'):
            size  = get_func_size(elf_file, f[0][:11])
            stack = get_stack_usage(elf_file, f[0][:11])
            max_stack = get_stack_usage(elf_file, f[1])
            # add code size for encryption and key schedule
            size  += get_func_size(elf_file, f[1])
            for i in range(2,len(f)-1):
                size += get_func_size(elf_file, f[i])
                max_stack = max(max_stack, get_stack_usage(elf_file, f[i]))
            # add the max stack usage for all specified functions
            stack += max_stack
            # add the round key size
            stack += f[-1]
        else:
            size  = get_func_size(elf_file, f[0])
            stack = get_stack_usage(elf_file, f[0])
        results.append((f[0], size, stack))
    
    print("Function Name                  | Stack | Size")
    print("---------------------------------------------")
    for function, size, stack in results:
        print(f"{function:<30} | {str(stack):<5} | {str(size)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze function sizes and stack consumption in an ELF file.")
    parser.add_argument("elf_file", help="Path to the ELF file.")
    parser.add_argument("--functions_file", help="Path to a JSON file containing the list of functions.", default=None)
    args = parser.parse_args()

    with open(args.functions_file, "r") as f:
        functions = json.load(f)

    analyze_functions(args.elf_file, functions)