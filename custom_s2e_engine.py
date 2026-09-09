#!/usr/bin/env python3
"""
Custom S2E Engine — a pattern-based IOCTL handler triage engine for Windows
kernel-mode drivers, shipped with a WinRing0.sys case study. It models the
dispatcher's per-IOCTL branching and classifies each handler's input-buffer
parsing with pattern rules. It does NOT perform symbolic execution: branches
are matched, not solved. Outputs vulnerability classifications, not
weaponised payloads.

Z3 is imported as a scaffold for a future constraint-solving backend; the
current pass does not invoke the solver.
"""

import os
import json
import time
import struct
import random
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import z3  # scaffold for a future constraint-solving backend (not yet invoked)

class SymbolicType(Enum):
    INTEGER = "int"
    POINTER = "ptr"
    BUFFER = "buffer"
    IOCTL_CODE = "ioctl"

@dataclass
class SymbolicVariable:
    name: str
    type: SymbolicType
    size: int
    value: Optional[Any] = None
    constraints: List[str] = None
    is_symbolic: bool = True
    
    def __post_init__(self):
        if self.constraints is None:
            self.constraints = []

@dataclass
class ExecutionState:
    state_id: int
    path: List[str]
    constraints: List[str]
    variables: Dict[str, SymbolicVariable]
    memory_accesses: List[Dict]
    exploits: List[Dict]
    pc: int = 0
    
    def __post_init__(self):
        if self.constraints is None:
            self.constraints = []
        if self.memory_accesses is None:
            self.memory_accesses = []
        if self.exploits is None:
            self.exploits = []

class CustomS2EEngine:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.states: List[ExecutionState] = []
        self.symbolic_variables: Dict[str, SymbolicVariable] = {}
        self.constraint_solver = z3.Solver()  # scaffold only; no constraints are added/checked yet
        self.state_counter = 0
        self.max_states = 1000
        self.max_depth = 50
        
        # Extract IOCTL codes from the binary
        self.ioctl_codes = self._extract_ioctl_codes_from_binary()
        
        # Kernel memory regions
        self.kernel_regions = [
            (0x80000000, 0x100000000, "Kernel Space"),
            (0x80000000, 0x80001000, "System Service Table"),
            (0x80000000, 0x80002000, "IDT/GDT"),
            (0x804d7000, 0x805d7000, "Kernel Code")
        ]
        
        # Exploit patterns
        self.exploit_patterns = {
            "ARBITRARY_READ": {"severity": "HIGH", "description": "Arbitrary kernel memory read"},
            "ARBITRARY_WRITE": {"severity": "CRITICAL", "description": "Arbitrary kernel memory write"},
            "PRIVILEGE_ESCALATION": {"severity": "CRITICAL", "description": "Privilege escalation to kernel"},
            "MEMORY_CORRUPTION": {"severity": "HIGH", "description": "Memory corruption in kernel"},
            "BUFFER_OVERFLOW": {"severity": "HIGH", "description": "Buffer overflow in kernel"},
            "NULL_DEREFERENCE": {"severity": "MEDIUM", "description": "Null pointer dereference"}
        }
    
    def _extract_ioctl_codes_from_binary(self) -> Dict[int, str]:
        """Extract IOCTL codes from the binary"""
        print("[CustomS2E] Extracting IOCTL codes from binary...")
        
        try:
            # Use the advanced binary analyzer
            from advanced_binary_analyzer import AdvancedBinaryAnalyzer
            
            analyzer = AdvancedBinaryAnalyzer(self.binary_path)
            if not analyzer.load_binary():
                print("[CustomS2E] Failed to load binary, using known IOCTL codes")
                return self._get_known_ioctl_codes()
            
            # Discover IOCTL codes
            ioctl_codes = analyzer.find_ioctl_codes_by_analysis()
            
            # Map IOCTL codes to symbolic names
            ioctl_dict = {}
            for code in ioctl_codes:
                name = self._get_ioctl_name(code)
                ioctl_dict[code] = name
                print(f"[CustomS2E] Found IOCTL: 0x{code:08X} - {name}")
            
            return ioctl_dict
            
        except Exception as e:
            print(f"[CustomS2E] Error extracting IOCTL codes: {e}")
            print("[CustomS2E] Using known IOCTL codes as fallback")
            return self._get_known_ioctl_codes()
    
    def _get_known_ioctl_codes(self) -> Dict[int, str]:
        """Return the table of known IOCTL codes (fallback)"""
        return {
            0x9C402580: "WR0_READ_MSR",
            0x9C402584: "WR0_WRITE_MSR", 
            0x9C402588: "WR0_READ_IO_PORT",
            0x9C40258C: "WR0_WRITE_IO_PORT",
            0x9C402590: "WR0_READ_MEMORY",
            0x9C402594: "WR0_WRITE_MEMORY",
            0x9C402598: "WR0_READ_PCI_CONFIG",
            0x9C40259C: "WR0_WRITE_PCI_CONFIG"
        }
    
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
        return ioctl_names.get(ioctl_code, f"UNKNOWN_IOCTL_0x{ioctl_code:08X}")
    
    def create_symbolic_variable(self, name: str, var_type: SymbolicType, size: int = 4) -> SymbolicVariable:
        """Create a symbolic variable"""
        var = SymbolicVariable(
            name=name,
            type=var_type,
            size=size,
            is_symbolic=True
        )
        self.symbolic_variables[name] = var
        print(f"[CustomS2E] Symbolic variable created: {name} ({var_type.value}, {size} bytes)")
        return var
    
    def create_initial_state(self) -> ExecutionState:
        """Create the initial execution state"""
        state = ExecutionState(
            state_id=self.state_counter,
            path=["INIT"],
            constraints=[],
            variables={},
            memory_accesses=[],
            exploits=[]
        )
        self.state_counter += 1
        self.states.append(state)
        return state
    
    def fork_state(self, parent_state: ExecutionState, condition: str) -> Tuple[ExecutionState, ExecutionState]:
        """Fork the state into true/false paths"""
        if len(self.states) >= self.max_states:
            print(f"[CustomS2E] Maximum states reached: {self.max_states}")
            return parent_state, parent_state
        
        # True path state
        true_state = ExecutionState(
            state_id=self.state_counter,
            path=parent_state.path + [f"{condition} = TRUE"],
            constraints=parent_state.constraints + [condition],
            variables=parent_state.variables.copy(),
            memory_accesses=parent_state.memory_accesses.copy(),
            exploits=parent_state.exploits.copy(),
            pc=parent_state.pc
        )
        self.state_counter += 1
        
        # False path state
        false_state = ExecutionState(
            state_id=self.state_counter,
            path=parent_state.path + [f"{condition} = FALSE"],
            constraints=parent_state.constraints + [f"NOT({condition})"],
            variables=parent_state.variables.copy(),
            memory_accesses=parent_state.memory_accesses.copy(),
            exploits=parent_state.exploits.copy(),
            pc=parent_state.pc
        )
        self.state_counter += 1
        
        self.states.extend([true_state, false_state])
        return true_state, false_state
    
    def evaluate_condition(self, condition: str, state: ExecutionState) -> bool:
        """Evaluate a condition and branch states accordingly"""
        print(f"[CustomS2E] Evaluating condition: {condition}")
        
        # Simple condition evaluation (real S2E would call Z3 here)
        if "ioctl_code" in condition:
            return self._evaluate_ioctl_condition(condition, state)
        elif "buffer_size" in condition:
            return self._evaluate_size_condition(condition, state)
        elif "input_buffer" in condition:
            return self._evaluate_pointer_condition(condition, state)
        else:
            # By default, explore both paths
            return True
    
    def _evaluate_ioctl_condition(self, condition: str, state: ExecutionState) -> bool:
        """Evaluate an IOCTL-code condition"""
        if "==" in condition:
            ioctl_code = int(condition.split("==")[1].strip(), 16)
            if ioctl_code in self.ioctl_codes:
                print(f"[CustomS2E] IOCTL code found: {self.ioctl_codes[ioctl_code]}")
                return True
        return False
    
    def _evaluate_size_condition(self, condition: str, state: ExecutionState) -> bool:
        """Evaluate a size-based condition"""
        if ">" in condition:
            size_limit = int(condition.split(">")[1].strip())
            print(f"[CustomS2E] Size condition: buffer_size > {size_limit}")
            return True
        return False
    
    def _evaluate_pointer_condition(self, condition: str, state: ExecutionState) -> bool:
        """Evaluate a pointer-validity condition"""
        if "!=" in condition and "NULL" in condition:
            print(f"[CustomS2E] Pointer condition: input_buffer != NULL")
            return True
        return False
    
    def check_memory_access(self, address: int, size: int, is_write: bool, state: ExecutionState) -> None:
        """Inspect a memory access and classify any matched patterns"""
        print(f"[CustomS2E] Memory access: 0x{address:x} ({'write' if is_write else 'read'}, {size} bytes)")
        
        # Kernel space kontrolü
        for start, end, name in self.kernel_regions:
            if start <= address < end:
                print(f"[CustomS2E] KERNEL ACCESS DETECTED: {name} (0x{address:x})")
                
                # Exploit pattern tespit et
                if is_write:
                    self._detect_arbitrary_write(address, size, state)
                else:
                    self._detect_arbitrary_read(address, size, state)
                
                # Memory access kaydet
                state.memory_accesses.append({
                    "address": address,
                    "size": size,
                    "is_write": is_write,
                    "region": name,
                    "pc": state.pc
                })
                break
    
    def _detect_arbitrary_write(self, address: int, size: int, state: ExecutionState) -> None:
        """Arbitrary write exploit'ini tespit et"""
        exploit = {
            "pattern": "ARBITRARY_WRITE",
            "severity": "CRITICAL",
            "address": address,
            "size": size,
            "description": "Ability to write arbitrary kernel memory",
            "path": state.path,
            "constraints": state.constraints
        }
        state.exploits.append(exploit)
        print(f"[CustomS2E] EXPLOIT DETECTED: ARBITRARY_WRITE at 0x{address:x}")
    
    def _detect_arbitrary_read(self, address: int, size: int, state: ExecutionState) -> None:
        """Arbitrary read exploit'ini tespit et"""
        exploit = {
            "pattern": "ARBITRARY_READ",
            "severity": "HIGH",
            "address": address,
            "size": size,
            "description": "Ability to read arbitrary kernel memory",
            "path": state.path,
            "constraints": state.constraints
        }
        state.exploits.append(exploit)
        print(f"[CustomS2E] EXPLOIT DETECTED: ARBITRARY_READ at 0x{address:x}")
    
    def analyze_ioctl_handler(self, ioctl_code: int, input_buffer: bytes, state: ExecutionState) -> None:
        """Analyze an IOCTL handler"""
        print(f"[CustomS2E] Analyzing IOCTL: 0x{ioctl_code:x} ({self.ioctl_codes.get(ioctl_code, 'UNKNOWN')})")
        
        # Dispatch on IOCTL code
        if ioctl_code == 0x9C402594:  # WRITE_MEMORY
            self._analyze_write_memory_ioctl(input_buffer, state)
        elif ioctl_code == 0x9C402590:  # READ_MEMORY
            self._analyze_read_memory_ioctl(input_buffer, state)
        elif ioctl_code == 0x9C402584:  # WRITE_MSR
            self._analyze_write_msr_ioctl(input_buffer, state)
        else:
            self._analyze_generic_ioctl(ioctl_code, input_buffer, state)
    
    def _analyze_write_memory_ioctl(self, input_buffer: bytes, state: ExecutionState) -> None:
        """WRITE_MEMORY IOCTL'ini analiz et"""
        print("[CustomS2E] Analyzing WRITE_MEMORY IOCTL")
        
        if len(input_buffer) >= 16:
            # Input buffer structure: memory_address(4) + write_size(4) + data_offset(4) + reserved(4)
            memory_address = struct.unpack('<I', input_buffer[0:4])[0]
            write_size = struct.unpack('<I', input_buffer[4:8])[0]
            
            print(f"[CustomS2E] Target address: 0x{memory_address:x}")
            print(f"[CustomS2E] Write size: {write_size}")
            
            # Kernel space check
            if memory_address >= 0x80000000:
                print("[CustomS2E] CRITICAL: Writing to kernel space!")
                self._detect_arbitrary_write(memory_address, write_size, state)
            
            # Buffer overflow check
            if write_size > 4096:
                print("[CustomS2E] WARNING: Large write size detected!")
                exploit = {
                    "pattern": "BUFFER_OVERFLOW",
                    "severity": "HIGH",
                    "size": write_size,
                    "description": "Potential buffer overflow in kernel",
                    "path": state.path
                }
                state.exploits.append(exploit)
    
    def _analyze_read_memory_ioctl(self, input_buffer: bytes, state: ExecutionState) -> None:
        """READ_MEMORY IOCTL'ini analiz et"""
        print("[CustomS2E] Analyzing READ_MEMORY IOCTL")
        
        if len(input_buffer) >= 12:
            # Input buffer structure: memory_address(4) + read_size(4) + reserved(4)
            memory_address = struct.unpack('<I', input_buffer[0:4])[0]
            read_size = struct.unpack('<I', input_buffer[4:8])[0]
            
            print(f"[CustomS2E] Source address: 0x{memory_address:x}")
            print(f"[CustomS2E] Read size: {read_size}")
            
            # Kernel space check
            if memory_address >= 0x80000000:
                print("[CustomS2E] CRITICAL: Reading from kernel space!")
                self._detect_arbitrary_read(memory_address, read_size, state)
    
    def _analyze_write_msr_ioctl(self, input_buffer: bytes, state: ExecutionState) -> None:
        """WRITE_MSR IOCTL'ini analiz et"""
        print("[CustomS2E] Analyzing WRITE_MSR IOCTL")
        
        if len(input_buffer) >= 12:
            # Input buffer structure: msr_register(4) + msr_value_low(4) + msr_value_high(4)
            msr_register = struct.unpack('<I', input_buffer[0:4])[0]
            msr_value_low = struct.unpack('<I', input_buffer[4:8])[0]
            msr_value_high = struct.unpack('<I', input_buffer[8:12])[0]
            
            print(f"[CustomS2E] MSR register: 0x{msr_register:x}")
            print(f"[CustomS2E] MSR value: 0x{msr_value_high:08x}{msr_value_low:08x}")
            
            # Critical MSR register check
            critical_msrs = [0x1A0, 0x1A1, 0x1A2]  # MTRR registers
            if msr_register in critical_msrs:
                print(f"[CustomS2E] WARNING: Writing to critical MSR 0x{msr_register:x}")
                exploit = {
                    "pattern": "PRIVILEGE_ESCALATION",
                    "severity": "CRITICAL",
                    "msr_register": msr_register,
                    "description": "Writing to critical MSR register",
                    "path": state.path
                }
                state.exploits.append(exploit)
    
    def _analyze_generic_ioctl(self, ioctl_code: int, input_buffer: bytes, state: ExecutionState) -> None:
        """Genel IOCTL analizi"""
        print(f"[CustomS2E] Analyzing generic IOCTL: 0x{ioctl_code:x}")
        
        # Buffer size check
        if len(input_buffer) > 1024:
            print("[CustomS2E] WARNING: Large input buffer detected!")
            exploit = {
                "pattern": "BUFFER_OVERFLOW",
                "severity": "HIGH",
                "size": len(input_buffer),
                "description": "Large input buffer may cause overflow",
                "path": state.path
            }
            state.exploits.append(exploit)
    
    def generate_exploit_payloads(self) -> List[Dict]:
        """Emit classification entries (one per detected pattern)"""
        print("[CustomS2E] Generating exploit payloads...")
        
        payloads = []
        
        for state in self.states:
            for exploit in state.exploits:
                if exploit["pattern"] == "ARBITRARY_WRITE":
                    payload = self._generate_write_payload(exploit)
                elif exploit["pattern"] == "ARBITRARY_READ":
                    payload = self._generate_read_payload(exploit)
                elif exploit["pattern"] == "PRIVILEGE_ESCALATION":
                    payload = self._generate_msr_payload(exploit)
                else:
                    payload = self._generate_generic_payload(exploit)
                
                payloads.append(payload)
        
        return payloads
    
    def _generate_write_payload(self, exploit: Dict) -> Dict:
        """Emit a write-class classification entry"""
        return {
            "ioctl_code": 0x9C402594,  # WRITE_MEMORY
            "input_buffer": struct.pack('<I', exploit["address"]) + struct.pack('<I', exploit["size"]) + b'\x00' * 8,
            "description": "Arbitrary kernel memory write",
            "severity": exploit["severity"],
            "constraints": exploit.get("constraints", [])
        }
    
    def _generate_read_payload(self, exploit: Dict) -> Dict:
        """Emit a read-class classification entry"""
        return {
            "ioctl_code": 0x9C402590,  # READ_MEMORY
            "input_buffer": struct.pack('<I', exploit["address"]) + struct.pack('<I', exploit["size"]) + b'\x00' * 4,
            "description": "Arbitrary kernel memory read",
            "severity": exploit["severity"],
            "constraints": exploit.get("constraints", [])
        }
    
    def _generate_msr_payload(self, exploit: Dict) -> Dict:
        """Emit an MSR-write classification entry"""
        return {
            "ioctl_code": 0x9C402584,  # WRITE_MSR
            "input_buffer": struct.pack('<I', exploit["msr_register"]) + b'\x41\x41\x41\x41' + b'\x42\x42\x42\x42',
            "description": "Critical MSR register write",
            "severity": exploit["severity"],
            "constraints": exploit.get("constraints", [])
        }
    
    def _generate_generic_payload(self, exploit: Dict) -> Dict:
        """Emit a generic classification entry"""
        return {
            "ioctl_code": 0x9C402580,  # READ_MSR
            "input_buffer": b'A' * 8,
            "description": exploit["description"],
            "severity": exploit["severity"],
            "constraints": exploit.get("constraints", [])
        }
    
    def run_analysis(self) -> Dict:
        """Ana analiz fonksiyonu"""
        print("[CustomS2E] Starting WinRing0.sys analysis...")
        
        # Create the initial state
        initial_state = self.create_initial_state()
        
        # Create symbolic variables
        ioctl_code = self.create_symbolic_variable("ioctl_code", SymbolicType.IOCTL_CODE)
        input_buffer = self.create_symbolic_variable("input_buffer", SymbolicType.BUFFER, 16)
        buffer_size = self.create_symbolic_variable("buffer_size", SymbolicType.INTEGER)
        
        # Walk through each IOCTL code
        for ioctl_code_val in self.ioctl_codes.keys():
            print(f"\n[CustomS2E] Testing IOCTL: 0x{ioctl_code_val:x}")
            
            # Exercise each IOCTL with multiple synthesised inputs
            test_inputs = self._generate_test_inputs(ioctl_code_val)
            
            for test_input in test_inputs:
                # Create a fresh state for this trial
                test_state = ExecutionState(
                    state_id=self.state_counter,
                    path=[f"IOCTL_0x{ioctl_code_val:x}"],
                    constraints=[],
                    variables={},
                    memory_accesses=[],
                    exploits=[]
                )
                self.state_counter += 1
                self.states.append(test_state)
                
                # IOCTL'i analiz et
                self.analyze_ioctl_handler(ioctl_code_val, test_input, test_state)
        
        # Collect results
        results = self._collect_results()
        
        print(f"[CustomS2E] Analysis completed. Found {len(results['exploits'])} exploits in {len(self.states)} states")
        
        return results
    
    def _generate_test_inputs(self, ioctl_code: int) -> List[bytes]:
        """Synthesise test inputs for an IOCTL"""
        inputs = []
        
        if ioctl_code == 0x9C402594:  # WRITE_MEMORY
            # Normal input
            inputs.append(struct.pack('<I', 0x10000000) + struct.pack('<I', 4) + b'\x00' * 8)
            # Kernel address input
            inputs.append(struct.pack('<I', 0x80000000) + struct.pack('<I', 4) + b'\x00' * 8)
            # Large size input
            inputs.append(struct.pack('<I', 0x10000000) + struct.pack('<I', 0x10000) + b'\x00' * 8)
            
        elif ioctl_code == 0x9C402590:  # READ_MEMORY
            # Normal input
            inputs.append(struct.pack('<I', 0x10000000) + struct.pack('<I', 4) + b'\x00' * 4)
            # Kernel address input
            inputs.append(struct.pack('<I', 0x80000000) + struct.pack('<I', 4) + b'\x00' * 4)
            
        elif ioctl_code == 0x9C402584:  # WRITE_MSR
            # Normal input
            inputs.append(struct.pack('<I', 0x1A0) + b'\x00' * 8)
            # Critical MSR input
            inputs.append(struct.pack('<I', 0x1A0) + b'\x41' * 8)
            
        else:
            # Generic input
            inputs.append(b'A' * 8)
            inputs.append(b'B' * 16)
            inputs.append(b'C' * 32)
        
        return inputs
    
    def _collect_results(self) -> Dict:
        """Aggregate the analysis output"""
        all_exploits = []
        for state in self.states:
            all_exploits.extend(state.exploits)
        
        # Exploit'leri kategorize et
        exploit_counts = {}
        for exploit in all_exploits:
            pattern = exploit["pattern"]
            exploit_counts[pattern] = exploit_counts.get(pattern, 0) + 1
        
        # Emit classifications
        payloads = self.generate_exploit_payloads()
        
        return {
            "total_states": len(self.states),
            "total_exploits": len(all_exploits),
            "exploits": all_exploits,
            "exploit_counts": exploit_counts,
            "payloads": payloads,
            "ioctl_analysis": self._analyze_ioctls()
        }
    
    def _analyze_ioctls(self) -> Dict:
        """IOCTL'leri analiz et"""
        ioctl_analysis = {}
        
        for ioctl_code, name in self.ioctl_codes.items():
            ioctl_exploits = []
            for state in self.states:
                for exploit in state.exploits:
                    if f"IOCTL_0x{ioctl_code:x}" in state.path[0]:
                        ioctl_exploits.append(exploit)
            
            ioctl_analysis[hex(ioctl_code)] = {
                "name": name,
                "exploit_count": len(ioctl_exploits),
                "exploits": ioctl_exploits
            }
        
        return ioctl_analysis
    
    def save_results(self, results: Dict, output_file: str = "custom_s2e_results.json"):
        """Save results to a file"""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"[CustomS2E] Results saved to: {output_file}")

def main():
    """Ana fonksiyon"""
    print("=== Custom S2E Engine - WinRing0.sys Analysis ===\n")
    
    # Check the binary file
    binary_path = "WinRing0.sys"
    if not os.path.exists(binary_path):
        print(f"Error: Binary file not found: {binary_path}")
        return
    
    # Construct the engine
    engine = CustomS2EEngine(binary_path)
    
    # Run the analysis
    results = engine.run_analysis()
    
    # Persist results
    engine.save_results(results)
    
    # Summary report
    print(f"\n=== Analysis Summary ===")
    print(f"Total states explored: {results['total_states']}")
    print(f"Total exploits found: {results['total_exploits']}")
    print(f"Exploit payloads generated: {len(results['payloads'])}")
    
    print(f"\nExploit breakdown:")
    for pattern, count in results['exploit_counts'].items():
        print(f"  {pattern}: {count}")

if __name__ == "__main__":
    main()
