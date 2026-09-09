#!/usr/bin/env python3
"""
WinRing0.sys Binary IOCTL Extractor
Extracts active IOCTL codes from a driver binary.
"""

import struct
import re
import os
from typing import List, Dict, Tuple

class BinaryIOCTLExtractor:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.binary_data = None
        self.ioctl_codes = []
        self.function_offsets = []
        
    def load_binary(self) -> bool:
        """Binary dosyasını yükle"""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            print(f"[IOCTL Extractor] Binary loaded: {len(self.binary_data)} bytes")
            return True
        except Exception as e:
            print(f"[IOCTL Extractor] Error loading binary: {e}")
            return False
    
    def find_ioctl_codes(self) -> List[int]:
        """Discover IOCTL codes in the binary"""
        if not self.binary_data:
            print("[IOCTL Extractor] Binary not loaded")
            return []
        
        print("[IOCTL Extractor] Searching for IOCTL codes...")
        
        # Search for known IOCTL patterns
        ioctl_patterns = [
            # CTL_CODE macro patterns
            b'\x80\x25\x9C\x40',  # 0x9C402580 pattern
            b'\x84\x25\x9C\x40',  # 0x9C402584 pattern
            b'\x88\x25\x9C\x40',  # 0x9C402588 pattern
            b'\x8C\x25\x9C\x40',  # 0x9C40258C pattern
            b'\x90\x25\x9C\x40',  # 0x9C402590 pattern
            b'\x94\x25\x9C\x40',  # 0x9C402594 pattern
            b'\x98\x25\x9C\x40',  # 0x9C402598 pattern
            b'\x9C\x25\x9C\x40',  # 0x9C40259C pattern
        ]
        
        found_codes = []
        
        for pattern in ioctl_patterns:
            offset = 0
            while True:
                pos = self.binary_data.find(pattern, offset)
                if pos == -1:
                    break
                
                # Extract the IOCTL code
                ioctl_code = struct.unpack('<I', pattern)[0]
                found_codes.append(ioctl_code)
                print(f"[IOCTL Extractor] Found IOCTL: 0x{ioctl_code:08X} at offset 0x{pos:08X}")
                
                offset = pos + 1
        
        # Hex pattern search
        hex_patterns = [
            b'\x80\x25\x9C\x40',  # Little endian
            b'\x40\x9C\x25\x80',  # Big endian
        ]
        
        for pattern in hex_patterns:
            offset = 0
            while True:
                pos = self.binary_data.find(pattern, offset)
                if pos == -1:
                    break
                
                # Extract the IOCTL code
                if pattern == b'\x80\x25\x9C\x40':
                    ioctl_code = 0x9C402580
                elif pattern == b'\x40\x9C\x25\x80':
                    ioctl_code = 0x80259C40
                else:
                    ioctl_code = struct.unpack('<I', pattern)[0]
                
                if ioctl_code not in found_codes:
                    found_codes.append(ioctl_code)
                    print(f"[IOCTL Extractor] Found IOCTL: 0x{ioctl_code:08X} at offset 0x{pos:08X}")
                
                offset = pos + 1
        
        # String pattern search (IOCTL names)
        string_patterns = [
            b'WR0_READ_MSR',
            b'WR0_WRITE_MSR',
            b'WR0_READ_IO_PORT',
            b'WR0_WRITE_IO_PORT',
            b'WR0_READ_MEMORY',
            b'WR0_WRITE_MEMORY',
            b'WR0_READ_PCI_CONFIG',
            b'WR0_WRITE_PCI_CONFIG',
        ]
        
        for pattern in string_patterns:
            pos = self.binary_data.find(pattern)
            if pos != -1:
                print(f"[IOCTL Extractor] Found string: {pattern.decode('ascii', errors='ignore')} at offset 0x{pos:08X}")
        
        # Search for DeviceIoControl call sites
        self._find_device_io_control_calls()
        
        # Search for the DispatchDeviceControl function
        self._find_dispatch_device_control()
        
        self.ioctl_codes = list(set(found_codes))  # Drop duplicates
        print(f"[IOCTL Extractor] Total unique IOCTL codes found: {len(self.ioctl_codes)}")
        
        return self.ioctl_codes
    
    def _find_device_io_control_calls(self):
        """Find DeviceIoControl call sites"""
        print("[IOCTL Extractor] Searching for DeviceIoControl calls...")
        
        # Search for DeviceIoControl import
        device_io_patterns = [
            b'DeviceIoControl',
            b'deviceiocontrol',
            b'DEVICEIOCONTROL',
        ]
        
        for pattern in device_io_patterns:
            pos = self.binary_data.find(pattern)
            if pos != -1:
                print(f"[IOCTL Extractor] Found DeviceIoControl reference at offset 0x{pos:08X}")
    
    def _find_dispatch_device_control(self):
        """Find the DispatchDeviceControl function"""
        print("[IOCTL Extractor] Searching for DispatchDeviceControl...")
        
        # DispatchDeviceControl patterns
        dispatch_patterns = [
            b'DispatchDeviceControl',
            b'dispatchdevicecontrol',
            b'DISPATCHDEVICECONTROL',
            b'IRP_MJ_DEVICE_CONTROL',
        ]
        
        for pattern in dispatch_patterns:
            pos = self.binary_data.find(pattern)
            if pos != -1:
                print(f"[IOCTL Extractor] Found DispatchDeviceControl reference at offset 0x{pos:08X}")
    
    def find_function_offsets(self) -> List[Tuple[int, str]]:
        """Find function offsets"""
        print("[IOCTL Extractor] Searching for function offsets...")
        
        functions = []
        
        # Search for DriverEntry pattern
        driver_entry_patterns = [
            b'DriverEntry',
            b'driverentry',
            b'DRIVERENTRY',
        ]
        
        for pattern in driver_entry_patterns:
            pos = self.binary_data.find(pattern)
            if pos != -1:
                functions.append((pos, "DriverEntry"))
                print(f"[IOCTL Extractor] Found DriverEntry at offset 0x{pos:08X}")
        
        # Search for DispatchDeviceControl pattern
        dispatch_patterns = [
            b'DispatchDeviceControl',
            b'dispatchdevicecontrol',
        ]
        
        for pattern in dispatch_patterns:
            pos = self.binary_data.find(pattern)
            if pos != -1:
                functions.append((pos, "DispatchDeviceControl"))
                print(f"[IOCTL Extractor] Found DispatchDeviceControl at offset 0x{pos:08X}")
        
        # Look for the IRP_MJ_DEVICE_CONTROL handler
        irp_patterns = [
            b'IRP_MJ_DEVICE_CONTROL',
            b'irp_mj_device_control',
        ]
        
        for pattern in irp_patterns:
            pos = self.binary_data.find(pattern)
            if pos != -1:
                functions.append((pos, "IRP_MJ_DEVICE_CONTROL"))
                print(f"[IOCTL Extractor] Found IRP_MJ_DEVICE_CONTROL at offset 0x{pos:08X}")
        
        self.function_offsets = functions
        return functions
    
    def analyze_ioctl_handlers(self) -> Dict:
        """Analyze IOCTL handlers"""
        print("[IOCTL Extractor] Analyzing IOCTL handlers...")
        
        analysis = {
            "ioctl_codes": self.ioctl_codes,
            "function_offsets": self.function_offsets,
            "handler_analysis": []
        }
        
        # Per-IOCTL analysis
        for ioctl_code in self.ioctl_codes:
            handler_info = {
                "ioctl_code": f"0x{ioctl_code:08X}",
                "name": self._get_ioctl_name(ioctl_code),
                "severity": self._assess_ioctl_severity(ioctl_code),
                "description": self._get_ioctl_description(ioctl_code)
            }
            analysis["handler_analysis"].append(handler_info)
        
        return analysis
    
    def _get_ioctl_name(self, ioctl_code: int) -> str:
        """Return a symbolic name for an IOCTL code"""
        ioctl_names = {
            0x9C402580: "WR0_READ_MSR",
            0x9C402584: "WR0_WRITE_MSR",
            0x9C402588: "WR0_READ_IO_PORT",
            0x9C40258C: "WR0_WRITE_IO_PORT",
            0x9C402590: "WR0_READ_MEMORY",
            0x9C402594: "WR0_WRITE_MEMORY",
            0x9C402598: "WR0_READ_PCI_CONFIG",
            0x9C40259C: "WR0_WRITE_PCI_CONFIG"
        }
        return ioctl_names.get(ioctl_code, "UNKNOWN")
    
    def _assess_ioctl_severity(self, ioctl_code: int) -> str:
        """Score the security severity of an IOCTL code"""
        write_ioctls = [0x9C402584, 0x9C40258C, 0x9C402594, 0x9C40259C]
        read_ioctls = [0x9C402580, 0x9C402588, 0x9C402590, 0x9C402598]
        
        if ioctl_code in write_ioctls:
            return "CRITICAL"
        elif ioctl_code in read_ioctls:
            return "HIGH"
        else:
            return "MEDIUM"
    
    def _get_ioctl_description(self, ioctl_code: int) -> str:
        """Return a human-readable description for an IOCTL code"""
        descriptions = {
            0x9C402580: "Read Model Specific Register",
            0x9C402584: "Write Model Specific Register",
            0x9C402588: "Read I/O Port",
            0x9C40258C: "Write I/O Port",
            0x9C402590: "Read Memory",
            0x9C402594: "Write Memory",
            0x9C402598: "Read PCI Configuration",
            0x9C40259C: "Write PCI Configuration"
        }
        return descriptions.get(ioctl_code, "Unknown operation")
    
    def generate_report(self) -> Dict:
        """Produce the analysis report"""
        if not self.binary_data:
            return {"error": "Binary not loaded"}
        
        # Discover IOCTL codes
        ioctl_codes = self.find_ioctl_codes()
        
        # Discover function offsets
        function_offsets = self.find_function_offsets()
        
        # Analyze handlers
        handler_analysis = self.analyze_ioctl_handlers()
        
        report = {
            "binary_info": {
                "file": self.binary_path,
                "size": len(self.binary_data),
                "analysis_timestamp": __import__('time').time()
            },
            "ioctl_codes": ioctl_codes,
            "function_offsets": function_offsets,
            "handler_analysis": handler_analysis["handler_analysis"],
            "summary": {
                "total_ioctls": len(ioctl_codes),
                "critical_ioctls": len([h for h in handler_analysis["handler_analysis"] if h["severity"] == "CRITICAL"]),
                "high_ioctls": len([h for h in handler_analysis["handler_analysis"] if h["severity"] == "HIGH"]),
                "functions_found": len(function_offsets)
            }
        }
        
        return report

def main():
    """Main entry point"""
    print("=== WinRing0.sys Binary IOCTL Extractor ===\n")
    
    binary_path = "WinRing0.sys"
    
    if not os.path.exists(binary_path):
        print(f"Error: Binary file not found: {binary_path}")
        return
    
    # Construct the extractor
    extractor = BinaryIOCTLExtractor(binary_path)
    
    # Load the binary
    if not extractor.load_binary():
        return
    
    # Generate the report
    report = extractor.generate_report()
    
    # Print results
    print(f"\n=== Analysis Report ===")
    print(f"Binary: {report['binary_info']['file']}")
    print(f"Size: {report['binary_info']['size']} bytes")
    print(f"Total IOCTLs found: {report['summary']['total_ioctls']}")
    print(f"Critical IOCTLs: {report['summary']['critical_ioctls']}")
    print(f"High IOCTLs: {report['summary']['high_ioctls']}")
    print(f"Functions found: {report['summary']['functions_found']}")
    
    print(f"\n=== IOCTL Codes ===")
    for ioctl in report['ioctl_codes']:
        print(f"0x{ioctl:08X}")
    
    print(f"\n=== Handler Analysis ===")
    for handler in report['handler_analysis']:
        print(f"{handler['ioctl_code']}: {handler['name']} ({handler['severity']}) - {handler['description']}")
    
    # Persist the report
    import json
    with open('binary_ioctl_analysis.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[IOCTL Extractor] Report saved to: binary_ioctl_analysis.json")

if __name__ == "__main__":
    main()
