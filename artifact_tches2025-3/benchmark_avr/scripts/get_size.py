import subprocess
import json
import sys
import csv
from collections import defaultdict

def run_avr_nm(elf_file):
    try:
        output = subprocess.check_output(
            ["avr-nm", "--print-size", "--size-sort", "--radix=d", elf_file],
            universal_newlines=True
        )
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error running avr-nm: {e}")
        sys.exit(1)

def parse_nm_output(nm_output):
    sizes = {}
    for line in nm_output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 4:
            address, size, type_, name = parts
            sizes[name] = int(size)
    return sizes

def load_functions_json(json_file):
    with open(json_file, 'r') as f:
        return json.load(f)

def sum_function_sizes(sizes_dict, functions_dict):
    cipher_totals = {}
    for cipher, functions in functions_dict.items():
        total = 0
        for func in functions:
            if func in sizes_dict:
                total += sizes_dict[func]
            else:
                print(f"Warning: function {func} not found in nm output.")
        cipher_totals[cipher] = total
    return cipher_totals

def write_csv(totals, output_csv_file):
    with open(output_csv_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["AEAD", "Total Size (bytes)"])
        for cipher, size in totals.items():
            writer.writerow([cipher, size])
    print(f"Results written to {output_csv_file}")

def main(elf_file, json_file):
    nm_output = run_avr_nm(elf_file)
    sizes = parse_nm_output(nm_output)
    functions = load_functions_json(json_file)
    totals = sum_function_sizes(sizes, functions)
    
    print("\nAEADs size summary:")
    for cipher, total_size in totals.items():
        print(f"{cipher}: {total_size} bytes")
    
    # Write CSV
    write_csv(totals, "summary.csv")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <file.elf> <functions.json>")
        sys.exit(1)
    
    elf_file = sys.argv[1]
    json_file = sys.argv[2]
    main(elf_file, json_file)
    