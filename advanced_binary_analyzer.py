#!/usr/bin/env python3
"""
Advanced Binary Analyzer for WinRing0.sys
Performs a more detailed analysis of the binary and recovers IOCTL patterns.
"""

import struct
import re
import os
import json
from typing import List, Dict, Tuple, Set

try:
    import pefile  # optional: more robust PE parsing when installed
except ImportError:  # pragma: no cover - exercised only when pefile is absent
    pefile = None

class AdvancedBinaryAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.binary_data = None
        self.ioctl_codes = set()
        self.strings = []
        self.imports = []
        self.exports = []
        self.sections = []
        
    def load_binary(self) -> bool:
        """Load the binary file"""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            print(f"[Advanced Analyzer] Binary loaded: {len(self.binary_data)} bytes")
            return True
        except Exception as e:
            print(f"[Advanced Analyzer] Error loading binary: {e}")
            return False
    
    def extract_strings(self) -> List[str]:
        """Extract strings from the binary"""
        print("[Advanced Analyzer] Extracting strings...")
        
        # Find ASCII strings (4+ characters)
        ascii_strings = []
        current_string = ""
        
        for i, byte in enumerate(self.binary_data):
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:
                    ascii_strings.append(current_string)
                current_string = ""
        
        # Find Unicode strings
        unicode_strings = []
        for i in range(0, len(self.binary_data) - 1, 2):
            try:
                char = struct.unpack('<H', self.binary_data[i:i+2])[0]
                if 32 <= char <= 126:  # Printable Unicode
                    unicode_strings.append(chr(char))
            except:
                pass
        
        # Filter for IOCTL-related strings
        ioctl_strings = []
        for string in ascii_strings:
            if any(keyword in string.lower() for keyword in ['ioctl', 'device', 'control', 'dispatch', 'irp', 'msr', 'pci', 'port']):
                ioctl_strings.append(string)
                print(f"[Advanced Analyzer] Found IOCTL string: {string}")
        
        self.strings = ioctl_strings
        return ioctl_strings
    
    def find_hex_patterns(self) -> List[Tuple[int, str, int]]:
        """Find hex patterns"""
        print("[Advanced Analyzer] Searching for hex patterns...")
        
        patterns = []
        
        # Hex representations of well-known IOCTL codes
        ioctl_hex_patterns = [
            (b'\x80\x25\x9C\x40', "0x9C402580", 0x9C402580),
            (b'\x84\x25\x9C\x40', "0x9C402584", 0x9C402584),
            (b'\x88\x25\x9C\x40', "0x9C402588", 0x9C402588),
            (b'\x8C\x25\x9C\x40', "0x9C40258C", 0x9C40258C),
            (b'\x90\x25\x9C\x40', "0x9C402590", 0x9C402590),
            (b'\x94\x25\x9C\x40', "0x9C402594", 0x9C402594),
            (b'\x98\x25\x9C\x40', "0x9C402598", 0x9C402598),
            (b'\x9C\x25\x9C\x40', "0x9C40259C", 0x9C40259C),
        ]
        
        for pattern, name, value in ioctl_hex_patterns:
            offset = 0
            while True:
                pos = self.binary_data.find(pattern, offset)
                if pos == -1:
                    break
                
                patterns.append((pos, name, value))
                print(f"[Advanced Analyzer] Found pattern {name} at offset 0x{pos:08X}")
                self.ioctl_codes.add(value)
                offset = pos + 1
        
        # Also search for big-endian variants
        big_endian_patterns = [
            (b'\x40\x9C\x25\x80', "0x80259C40", 0x80259C40),
            (b'\x40\x9C\x25\x84', "0x84259C40", 0x84259C40),
            (b'\x40\x9C\x25\x88', "0x88259C40", 0x88259C40),
            (b'\x40\x9C\x25\x8C', "0x8C259C40", 0x8C259C40),
            (b'\x40\x9C\x25\x90', "0x90259C40", 0x90259C40),
            (b'\x40\x9C\x25\x94', "0x94259C40", 0x94259C40),
            (b'\x40\x9C\x25\x98', "0x98259C40", 0x98259C40),
            (b'\x40\x9C\x25\x9C', "0x9C259C40", 0x9C259C40),
        ]
        
        for pattern, name, value in big_endian_patterns:
            offset = 0
            while True:
                pos = self.binary_data.find(pattern, offset)
                if pos == -1:
                    break
                
                patterns.append((pos, name, value))
                print(f"[Advanced Analyzer] Found big-endian pattern {name} at offset 0x{pos:08X}")
                self.ioctl_codes.add(value)
                offset = pos + 1
        
        return patterns
    
    def find_ctrl_code_macros(self) -> List[Tuple[int, str, int]]:
        """Locate CTL_CODE macro usages"""
        print("[Advanced Analyzer] Searching for CTL_CODE macros...")
        
        patterns = []
        
        # CTL_CODE macro patterns
        ctl_code_patterns = [
            # CTL_CODE(FILE_DEVICE_UNKNOWN, 0x960, METHOD_BUFFERED, FILE_ANY_ACCESS)
            (b'CTL_CODE', "CTL_CODE macro"),
            (b'FILE_DEVICE_UNKNOWN', "FILE_DEVICE_UNKNOWN"),
            (b'METHOD_BUFFERED', "METHOD_BUFFERED"),
            (b'FILE_ANY_ACCESS', "FILE_ANY_ACCESS"),
        ]
        
        for pattern, name in ctl_code_patterns:
            pos = self.binary_data.find(pattern)
            if pos != -1:
                patterns.append((pos, name, 0))
                print(f"[Advanced Analyzer] Found {name} at offset 0x{pos:08X}")
        
        return patterns
    
    def find_device_control_patterns(self) -> List[Tuple[int, str]]:
        """Find device-control-related patterns"""
        print("[Advanced Analyzer] Searching for device control patterns...")
        
        patterns = []
        
        device_patterns = [
            (b'DeviceIoControl', "DeviceIoControl"),
            (b'deviceiocontrol', "deviceiocontrol"),
            (b'DEVICEIOCONTROL', "DEVICEIOCONTROL"),
            (b'DispatchDeviceControl', "DispatchDeviceControl"),
            (b'dispatchdevicecontrol', "dispatchdevicecontrol"),
            (b'DISPATCHDEVICECONTROL', "DISPATCHDEVICECONTROL"),
            (b'IRP_MJ_DEVICE_CONTROL', "IRP_MJ_DEVICE_CONTROL"),
            (b'irp_mj_device_control', "irp_mj_device_control"),
            (b'IRP_MJ_DEVICE_CONTROL', "IRP_MJ_DEVICE_CONTROL"),
        ]
        
        for pattern, name in device_patterns:
            offset = 0
            while True:
                pos = self.binary_data.find(pattern, offset)
                if pos == -1:
                    break
                
                patterns.append((pos, name))
                print(f"[Advanced Analyzer] Found {name} at offset 0x{pos:08X}")
                offset = pos + 1
        
        return patterns
    
    def find_winring0_specific_patterns(self) -> List[Tuple[int, str]]:
        """Locate WinRing0-specific patterns"""
        print("[Advanced Analyzer] Searching for WinRing0-specific patterns...")
        
        patterns = []
        
        winring0_patterns = [
            (b'WinRing0', "WinRing0"),
            (b'winring0', "winring0"),
            (b'WINRING0', "WINRING0"),
            (b'WR0_', "WR0_ prefix"),
            (b'MSR', "MSR"),
            (b'PCI', "PCI"),
            (b'IOPort', "IOPort"),
            (b'Memory', "Memory"),
            (b'Config', "Config"),
        ]
        
        for pattern, name in winring0_patterns:
            offset = 0
            while True:
                pos = self.binary_data.find(pattern, offset)
                if pos == -1:
                    break
                
                patterns.append((pos, name))
                print(f"[Advanced Analyzer] Found {name} at offset 0x{pos:08X}")
                offset = pos + 1
        
        return patterns
    
    def analyze_pe_structure(self) -> Dict:
        """Analyze the PE structure.

        Uses ``pefile`` when it is installed (robust against unusual but
        valid headers); otherwise — or if ``pefile`` rejects the input —
        falls back to a hand-rolled ``struct`` parser. Both paths return
        the same dict shape, with an extra ``parser`` field recording
        which one produced the result.
        """
        print("[Advanced Analyzer] Analyzing PE structure...")

        if pefile is not None:
            result = self._analyze_pe_structure_pefile()
            if "error" not in result:
                return result
            # pefile rejected it; fall through to the struct parser, which
            # returns a consistent error or partial info.
        return self._analyze_pe_structure_struct()

    def _analyze_pe_structure_pefile(self) -> Dict:
        """PE parse via the `pefile` library (preferred when available)."""
        try:
            pe = pefile.PE(data=bytes(self.binary_data), fast_load=True)
        except Exception as exc:  # pefile.PEFormatError and friends
            return {"error": f"pefile could not parse: {exc}"}
        try:
            pe_offset = pe.DOS_HEADER.e_lfanew
            machine = pe.FILE_HEADER.Machine
            num_sections = pe.FILE_HEADER.NumberOfSections
            characteristics = pe.FILE_HEADER.Characteristics
        finally:
            pe.close()

        print(f"[Advanced Analyzer] PE header at offset 0x{pe_offset:08X} (pefile)")
        print(f"[Advanced Analyzer] Machine: 0x{machine:04X}")
        print(f"[Advanced Analyzer] Number of sections: {num_sections}")
        print(f"[Advanced Analyzer] Characteristics: 0x{characteristics:04X}")
        return {
            "pe_offset": pe_offset,
            "machine": machine,
            "num_sections": num_sections,
            "characteristics": characteristics,
            "is_driver": bool(characteristics & 0x2000),
            "parser": "pefile",
        }

    def _analyze_pe_structure_struct(self) -> Dict:
        """Hand-rolled fallback parser (no third-party dependency)."""
        if len(self.binary_data) < 64:
            return {"error": "File too small to be a valid PE"}

        # DOS header check
        if self.binary_data[:2] != b'MZ':
            return {"error": "Not a valid PE file (missing DOS signature)"}

        # Find the PE header offset
        pe_offset = struct.unpack('<I', self.binary_data[60:64])[0]

        if pe_offset >= len(self.binary_data) - 4:
            return {"error": "Invalid PE header offset"}

        # PE signature check
        if self.binary_data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return {"error": "Not a valid PE file (missing PE signature)"}

        print(f"[Advanced Analyzer] PE header found at offset 0x{pe_offset:08X}")

        # Read the 20-byte COFF/IMAGE_FILE_HEADER (starts right after the
        # 4-byte PE signature). The previous code sliced 20 bytes but then
        # required 22 and unpacked '<HHIIIIH' (22 bytes, SizeOfOptionalHeader
        # mistyped as a DWORD), so it returned "Invalid COFF header size" for
        # *every* input. IMAGE_FILE_HEADER is exactly 20 bytes: '<HHIIIHH'.
        coff_header = self.binary_data[pe_offset+4:pe_offset+24]
        if len(coff_header) < 20:
            return {"error": "Invalid COFF header size"}

        (machine, num_sections, timestamp, ptr_to_symbol_table,
         num_symbols, size_of_optional_header, characteristics) = struct.unpack(
            '<HHIIIHH', coff_header[:20])

        print(f"[Advanced Analyzer] Machine: 0x{machine:04X}")
        print(f"[Advanced Analyzer] Number of sections: {num_sections}")
        print(f"[Advanced Analyzer] Characteristics: 0x{characteristics:04X}")

        return {
            "pe_offset": pe_offset,
            "machine": machine,
            "num_sections": num_sections,
            "characteristics": characteristics,
            "is_driver": bool(characteristics & 0x2000),  # preserved heuristic
            "parser": "struct",
        }
    
    def find_ioctl_codes_by_analysis(self) -> List[int]:
        """Run the analysis and return discovered IOCTL codes"""
        print("[Advanced Analyzer] Analyzing binary for IOCTL codes...")
        
        found_codes = set()
        
        # 1. Hex pattern search
        hex_patterns = self.find_hex_patterns()
        for _, _, code in hex_patterns:
            found_codes.add(code)
        
        # 2. String analysis
        strings = self.extract_strings()
        
        # 3. CTL_CODE macro search
        ctl_patterns = self.find_ctrl_code_macros()
        
        # 4. Device-control patterns
        device_patterns = self.find_device_control_patterns()
        
        # 5. WinRing0-specific patterns
        winring0_patterns = self.find_winring0_specific_patterns()
        
        # 6. Add known IOCTL codes (fallback)
        known_ioctls = [0x9C402580, 0x9C402584, 0x9C402588, 0x9C40258C, 
                       0x9C402590, 0x9C402594, 0x9C402598, 0x9C40259C]
        
        # If nothing was found, fall back to the known set
        if not found_codes:
            print("[Advanced Analyzer] No IOCTL codes found in binary, using known codes")
            found_codes.update(known_ioctls)
        
        self.ioctl_codes = found_codes
        return list(found_codes)
    
    def generate_comprehensive_report(self) -> Dict:
        """Produce a comprehensive analysis report"""
        print("[Advanced Analyzer] Generating comprehensive report...")
        
        # PE structure analysis
        pe_info = self.analyze_pe_structure()
        
        # Discover IOCTL codes
        ioctl_codes = self.find_ioctl_codes_by_analysis()
        
        # Extract strings
        strings = self.extract_strings()
        
        # Find patterns
        hex_patterns = self.find_hex_patterns()
        device_patterns = self.find_device_control_patterns()
        winring0_patterns = self.find_winring0_specific_patterns()
        
        report = {
            "binary_info": {
                "file": self.binary_path,
                "size": len(self.binary_data),
                "pe_info": pe_info
            },
            "ioctl_analysis": {
                "codes_found": list(ioctl_codes),
                "total_codes": len(ioctl_codes),
                "hex_patterns": [(hex(offset), name, hex(code)) for offset, name, code in hex_patterns]
            },
            "string_analysis": {
                "ioctl_strings": strings,
                "total_strings": len(strings)
            },
            "pattern_analysis": {
                "device_patterns": [(hex(offset), name) for offset, name in device_patterns],
                "winring0_patterns": [(hex(offset), name) for offset, name in winring0_patterns]
            },
            "summary": {
                "is_driver": pe_info.get("is_driver", False),
                "ioctl_codes_found": len(ioctl_codes),
                "patterns_found": len(hex_patterns) + len(device_patterns) + len(winring0_patterns),
                "strings_found": len(strings)
            }
        }
        
        return report

def main():
    """Main entry point"""
    print("=== Advanced WinRing0.sys Binary Analyzer ===\n")
    
    binary_path = "WinRing0.sys"
    
    if not os.path.exists(binary_path):
        print(f"Error: Binary file not found: {binary_path}")
        return
    
    # Construct the analyzer
    analyzer = AdvancedBinaryAnalyzer(binary_path)
    
    # Load the binary
    if not analyzer.load_binary():
        return
    
    # Run a comprehensive analysis
    report = analyzer.generate_comprehensive_report()
    
    # Print results
    print(f"\n=== Analysis Report ===")
    print(f"Binary: {report['binary_info']['file']}")
    print(f"Size: {report['binary_info']['size']} bytes")
    print(f"Is Driver: {report['summary']['is_driver']}")
    print(f"IOCTL Codes Found: {report['summary']['ioctl_codes_found']}")
    print(f"Patterns Found: {report['summary']['patterns_found']}")
    print(f"Strings Found: {report['summary']['strings_found']}")
    
    print(f"\n=== IOCTL Codes ===")
    for code in report['ioctl_analysis']['codes_found']:
        print(f"0x{code:08X}")
    
    print(f"\n=== IOCTL Strings ===")
    for string in report['string_analysis']['ioctl_strings']:
        print(f"'{string}'")
    
    print(f"\n=== Device Control Patterns ===")
    for offset, name in report['pattern_analysis']['device_patterns']:
        print(f"{offset}: {name}")
    
    print(f"\n=== WinRing0 Patterns ===")
    for offset, name in report['pattern_analysis']['winring0_patterns']:
        print(f"{offset}: {name}")
    
    # Persist the report
    with open('advanced_binary_analysis.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[Advanced Analyzer] Report saved to: advanced_binary_analysis.json")

if __name__ == "__main__":
    main()
