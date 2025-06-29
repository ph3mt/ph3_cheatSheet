#!/usr/bin/env python3
import sys
from pathlib import Path

def clean_name(line):
    return ''.join(c for c in line if c == " " or c.isalpha())

def generate_variants(fname, lname):
    print(fname + lname)           # johndoe
    print(lname + fname)           # doejohn
    print(f"{fname}.{lname}")      # john.doe
    print(f"{lname}.{fname}")      # doe.john
    print(lname + fname[0])        # doej
    print(fname[0] + lname)        # jdoe
    print(lname[0] + fname)        # djoe
    print(f"{fname[0]}.{lname}")   # j.doe
    print(f"{lname[0]}.{fname}")   # d.john
    print(fname)                   # john
    print(lname)                   # doe

def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} names.txt")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    if not input_file.exists():
        print(f"{input_file} not found")
        sys.exit(1)

    with input_file.open(encoding='utf-8') as file:
        for line in file:
            name = clean_name(line).strip()
            tokens = name.lower().split()

            if not tokens:
                continue

            fname = tokens[0]
            lname = tokens[-1]

            generate_variants(fname, lname)

if __name__ == "__main__":
    main()
