import pefile
import math
import os
import argparse
import hashlib
from config import SUSPICIOUS_ENTROPY_MINVALUE

# Known packer section names
SUSPICIOUS_SECTIONS = {
    '.upx', 'UPX0', 'UPX1', 'MPRESS1', 'ASPack', '.packed'
}

USUAL_SECTIONS = {
    '.text','.rdata', '.data', '.pdata', '.rsrc',
    '.edata','.idata','.reloc', '.tls', '.bss',
    '.CRT', '.gfids'
}

def print_pe_spec(data, f):
    def writeln(line=""):
        f.write(f"# {line}\n")

    # File name
    writeln("File Information")
    writeln("-" * 50)
    writeln(f"Path: {data.get('name')}")
    writeln()

    # Hashes
    writeln("File Hashes")
    writeln("-" * 50)
    for algo, value in data.get("file_hashes", {}).items():
        writeln(f"{algo.upper():8}: {value}")
    writeln()

    # Sections
    writeln("PE Sections")
    writeln("-" * 50)
    for section in data.get("sections", []):
        writeln(f"Section Name : {section.get('name')}")
        writeln(f"  Suspicious Section Name : {section.get('suspectName')}")
        writeln(f"  Unusual Section Name : {section.get('unusualName')}")
        writeln(f"  Entropy     : {section.get('ent'):.4f}")
        writeln(f"  Suspicious Entropy : {section.get('suspiciousEntropy')}")
        writeln(f"  Raw Size    : {section.get('rawSize')}")
        writeln(f"  Virtual Size: {section.get('virtualSize')}")
        writeln()



def get_file_hashes(path):
    with open(path, "rb") as f:
        data = f.read()

    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }


def section_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        return {"file": file_path, "error": str(e)}
    score = 0
    details = {}

    pe_spec = {}
    
    pe_spec["name"] = file_path
    pe_spec["file_hashes"] = get_file_hashes(file_path)
    pe_spec["sections"] = []
    for section in pe.sections:
        unusual_name = "false"
        suspect_name = "false"
        suspicious_entropy = "false"
        section_name = section.Name.decode(errors='ignore').rstrip('\x00')
        entropy = section_entropy(section.get_data())
        if(section_name not in USUAL_SECTIONS): unusual_name = "true"
        if(section_name in SUSPICIOUS_SECTIONS): suspect_name = "true"
        if(entropy > SUSPICIOUS_ENTROPY_MINVALUE): suspicious_entropy = "true"
        sec = {
            "name": section_name,
            "ent": entropy,
            "suspiciousEntropy": suspicious_entropy,
            "rawSize": section.SizeOfRawData,
            "virtualSize": section.Misc_VirtualSize,
            "unusualName": unusual_name,
            "suspectName": suspect_name
        }
        pe_spec["sections"].append(sec)
    return pe_spec

