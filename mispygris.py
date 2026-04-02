#!/usr/bin/env python3
import sys
import argparse
import string
import math
from collections import Counter
import os
from config import PATTERNS, ARTIFACT_FILE_NAME
from misp_utils import  init_misp_cert, query_misp
from metadata import analyze_pe, print_pe_spec


def read_iocs(outfile):
    result = []
    for line in outfile:
        line = line.strip()
        if line and not line.startswith("#"):
            if ":" in line:
                _, second = line.split(":", 1)
                result.append(second.strip())
    return result

def confirm_override(path: str) -> bool:
    """Ask user confirmation before overwriting a file."""
    if not os.path.exists(path):
        return True

    choice = input("are you sure to override the file? Y/N ").strip().lower()
    return choice == "y"


def string_entropy(s: str) -> float:
    """
    Compute the Shannon entropy of a string.
    Entropy is returned in bits.
    """
    if not s:
        return 0.0
    
    counts = Counter(s)
    length = len(s)
    
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy

def extract_strings(data, min_length=4):
    """Extract printable strings from binary data."""
    result = []
    current = []

    printable = set(string.printable) - set("\r\n\t\x0b\x0c")  # Exclude control chars

    for byte in data:
        char = chr(byte)
        if char in printable:
            current.append(char)
        else:
            if len(current) >= min_length:
                result.append("".join(current))
            current = []
    # Handle last possible string
    if len(current) >= min_length:
        result.append("".join(current))

    return result


def process_file(filename, min_length, mode, outfile=None):
    pe_spec = analyze_pe(filename)
    print_pe_spec(pe_spec,outfile)
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        sys.exit(f"Error: File not found: {filename}")
    
    strings = extract_strings(data, min_length)
    # Extract hash value from pe to add it as ioc
    for algo, value in pe_spec.get("file_hashes", {}).items():
        outfile.write(f"{algo}:{value}" + "\n")
    # Match extracted lines with regex
    for s in strings:
        for label, regex in PATTERNS:
            match = regex.search(s)
            if match:
                line = f"{label}:{match.group()}"
                outfile.write(line + "\n")

def process_folder(folder_path: str, min_length: int, mode: str, outfile=None):
    """
    Recursively process all files in a folder.
    Each file will be analyzed using process_file.
    """
    if not os.path.isdir(folder_path):
        print(f"Warning: {folder_path} is not a directory, skipping.")
        return

    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                print(f"Processing file: {file_path}")
                process_file(file_path, min_length, mode, outfile)
            except Exception as e:
                print(f"Error processing {file_path}: {e}")

def main():

    parser = argparse.ArgumentParser(
        description="Extract printable strings from binary files and interact with a MISP instance.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
    Examples:
      Extract strings from a single file and populate MISP:
       mispygris.py -f sample.bin -m populate

      Read IOC from a file and query MISP:
       mispygris.py -m query --misp-url https://misp.local --misp-key ABC123 --misp-cert cert.crt
    """
    )
    parser.add_argument("-f", "--file", help="Path to a binary file")
    parser.add_argument("-d", "--folder", help="Path to a folder containing binary files")
    parser.add_argument("-m","--mode",choices=["populate", "query"],required=True,help="populate: store artifacts, query: check on MISP instance")
    parser.add_argument("-n", "--min-length", type=int, default=4, help="Minimum string length (default: 4)")
    parser.add_argument("--misp-url", help="MISP instance URL")
    parser.add_argument("--misp-key", help="MISP API key")
    parser.add_argument("--misp-cert", help="SSL certificate", default=False)
    parser.add_argument("--ioc-file", default=ARTIFACT_FILE_NAME, help=f"IOC input file for query mode (default: {ARTIFACT_FILE_NAME})"
)
    args = parser.parse_args()

    outfile = None
    misp = None

    # Query MISP instance with IOCS extracted from file
    if args.mode == "query":
        if not args.misp_url or not args.misp_key:
            parser.error("--misp-url and --misp-key are required when mode is 'query'")
        misp = init_misp_cert(args.misp_url, args.misp_key, args.misp_cert)
        try:
            with open(ARTIFACT_FILE_NAME, "r") as f:
                iocs = read_iocs(f)
                malicious_list = query_misp(misp, iocs)
                for elem in malicious_list:
                    print(elem[0],elem[1]["id"], elem[1]["info"])
        except FileNotFoundError:
            raise FileNotFoundError('File "artifacts.txt" does not exist')

    # Populate the IOCS file with extracted iocs from the binary
    if args.mode == "populate":
        if not confirm_override(ARTIFACT_FILE_NAME):
            sys.exit("Aborted by user.")

        outfile = open(ARTIFACT_FILE_NAME, "w", encoding="utf-8")

        try:
            if args.file:
                process_file(args.file, args.min_length, args.mode, outfile)
            elif args.folder:
                process_folder(args.folder, args.min_length, args.mode, outfile)
        finally:
            if outfile:
                outfile.close()

if __name__ == "__main__":
    main()
