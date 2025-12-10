#!/usr/bin/env python3
"""
BLE Device Vulnerability Detailed Analysis Script - Intelligent Analysis Version (Fixed Misjudgment Issues + PCAP Saving)
Includes intelligent BLE protocol response analysis to avoid misjudging normal interactions as errors
Supports PCAP log saving
"""

import sys
import time
import statistics
import datetime
import re
import json
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

try:
    import constant
    from fuzzing.FuzzingBLESUL import FuzzedParam, FuzzingBLESUL
except ImportError as e:
    print(Fore.RED + f"Import failed: {e}")
    sys.exit(1)

class IntelligentBLEResponseAnalyzer:
    """Intelligent BLE Response Analyzer - Accurately identify protocol status"""
    
    # BLE HCI error code definitions
    HCI_ERROR_CODES = {
        0x00: "Success",
        0x01: "Unknown HCI Command",
        0x02: "Unknown Connection Identifier",
        0x03: "Hardware Failure",
        0x04: "Page Timeout",
        0x05: "Authentication Failure",
        0x06: "Pin or Key Missing",
        0x07: "Memory Capacity Exceeded",
        0x08: "Connection Timeout",
        0x09: "Connection Limit Exceeded",
        0x0A: "Synchronous Connection Limit Exceeded",
        0x0B: "ACL Connection Already Exists",
        0x0C: "Command Disallowed",
        0x0D: "Connection Rejected due to Limited Resources",
        0x0E: "Connection Rejected due to Security Reasons",
        0x0F: "Connection Rejected due to Unacceptable BD_ADDR",
        0x10: "Connection Accept Timeout Exceeded",
        0x11: "Unsupported Feature or Parameter Value",
        0x12: "Invalid HCI Command Parameters",
        0x13: "Remote User Terminated Connection",
        0x14: "Remote Device Terminated Connection due to Low Resources",
        0x15: "Remote Device Terminated Connection due to Power Off",
        0x16: "Connection Terminated by Local Host",
        0x17: "Repeated Attempts",
        0x18: "Pairing Not Allowed",
        0x19: "Unknown LMP PDU",
        0x1A: "Unsupported Remote Feature / Unsupported LMP Feature",
        0x1B: "SCO Offset Rejected",
        0x1C: "SCO Interval Rejected",
        0x1D: "SCO Air Mode Rejected",
        0x1E: "Invalid LMP Parameters / Invalid LL Parameters",
        0x1F: "Unspecified Error",
        0x20: "Unsupported LMP Parameter Value / Unsupported LL Parameter Value",
        0x21: "Role Change Not Allowed",
        0x22: "LMP Response Timeout / LL Response Timeout",
        0x23: "LMP Error Transaction Collision / LL Procedure Collision",
        0x24: "LMP PDU Not Allowed",
        0x25: "Encryption Mode Not Acceptable",
        0x26: "Link Key Cannot be Changed",
        0x27: "Requested QoS Not Supported",
        0x28: "Instant Passed",
        0x29: "Pairing with Unit Key Not Supported",
        0x2A: "Different Transaction Collision",
        0x2B: "Reserved",
        0x2C: "QoS Unacceptable Parameter",
        0x2D: "QoS Rejected",
        0x2E: "Channel Classification Not Supported",
        0x2F: "Insufficient Security",
        0x30: "Parameter Out Of Mandatory Range",
        0x31: "Reserved",
        0x32: "Role Switch Pending",
        0x33: "Reserved",
        0x34: "Reserved Slot Violation",
        0x35: "Role Switch Failed",
        0x36: "Extended Inquiry Response Too Large",
        0x37: "Secure Simple Pairing Not Supported by Host",
        0x38: "Host Busy - Pairing",
        0x39: "Connection Rejected due to No Suitable Channel Found",
        0x3A: "Controller Busy",
        0x3B: "Unacceptable Connection Parameters",
        0x3C: "Advertising Timeout",
        0x3D: "Connection Terminated due to MIC Failure",
        0x3E: "Connection Failed to be Established",
        0x3F: "MAC Connection Failed",
    }
    
    # BLE Link Layer (LL) PDU types - indicate connection status
    LL_CONNECTION_PDUS = {
        "LL_SLAVE_FEATURE_REQ": "Slave Feature Request - Connection established",
        "LL_FEATURE_RSP": "Feature Response",
        "LL_VERSION_IND": "Version Indication",
        "LL_PING_REQ": "Ping Request",
        "LL_PING_RSP": "Ping Response",
        "LL_LENGTH_REQ": "Length Request",
        "LL_LENGTH_RSP": "Length Response",
        "LL_ENC_REQ": "Encryption Request",
        "LL_ENC_RSP": "Encryption Response",
        "LL_START_ENC_REQ": "Start Encryption Request",
        "LL_START_ENC_RSP": "Start Encryption Response",
        "LL_TERMINATE_IND": "Connection Termination Indication",
    }
    
    # Connection establishment success indicators
    CONNECTION_SUCCESS_INDICATORS = [
        "LL_SLAVE_FEATURE_REQ",
        "LL_FEATURE_RSP", 
        "LL_VERSION_IND",
        "ATT_Exchange_MTU_Request",
        "ATT_Exchange_MTU_Response",
        "connected",
        "connection",
        "CONNECTED",
        "CONNECTION"
    ]
    
    # Connection failure indicators
    CONNECTION_FAILURE_INDICATORS = [
        "ERROR",
        "error",
        "FAILED",
        "failed",
        "REJECT",
        "reject",
        "TIMEOUT",
        "timeout"
    ]
    
    def __init__(self):
        self.error_history = []
        self.connection_history = []
        self.protocol_analysis = []
        
    def intelligent_analyze_response(self, response, operation="Unknown", context=None):
        """
        Intelligently analyze BLE response
        
        Args:
            response: Response object
            operation: Operation name
            context: Context information (e.g., phase of attack testing)
            
        Returns:
            dict: Intelligent analysis results
        """
        analysis = {
            "operation": operation,
            "timestamp": datetime.datetime.now().isoformat(),
            "raw_response": str(response) if response else "None",
            "response_type": type(response).__name__ if response else "None",
            "status": "unknown",
            "protocol_layer": self._detect_protocol_layer(response, operation),
            "is_error": False,
            "error_details": [],
            "success_indicators": [],
            "warning_indicators": [],
            "vulnerability_hints": [],
            "recommended_action": None,
            "context": context
        }
        
        if response is None:
            analysis["status"] = "no_response"
            analysis["is_error"] = True
            analysis["error_details"].append("No response from device")
            analysis["recommended_action"] = "Check if device is online or restart the device"
            return analysis
        
        response_str = str(response)
        analysis["response_summary"] = self._summarize_response(response_str)
        
        # 1. Intelligent status judgment (based on operation type)
        analysis.update(self._analyze_by_operation(response_str, operation))
        
        # 2. Error code analysis
        error_codes = self._extract_error_codes(response_str)
        if error_codes:
            analysis["error_details"].extend(error_codes)
            analysis["is_error"] = True
        
        # 3. Vulnerability hint analysis
        vulnerability_hints = self._detect_vulnerability_hints(response_str, operation, context)
        if vulnerability_hints:
            analysis["vulnerability_hints"].extend(vulnerability_hints)
        
        # 4. Update final status
        if not analysis["status"] or analysis["status"] == "unknown":
            analysis["status"] = self._determine_final_status(analysis)
        
        # 5. Recommended action
        analysis["recommended_action"] = self._suggest_action(analysis)
        
        # Record analysis history
        self.protocol_analysis.append(analysis)
        
        return analysis
    
    def _detect_protocol_layer(self, response, operation):
        """Detect protocol layer"""
        if not response:
            return "unknown"
        
        response_str = str(response)
        
        # Judge based on operation type
        operation_to_layer = {
            "scan_req": "HCI",
            "connection_request": "HCI/L2CAP/LL",
            "length_request": "LL (Link Layer)",
            "mtu_request": "ATT/L2CAP",
            "pairing_request": "SM (Security Manager)",
            "feature_request": "LL (Link Layer)",
            "version_request": "LL (Link Layer)",
        }
        
        # Judge based on response content
        if "LL_" in response_str:
            return "LL (Link Layer)"
        elif "ATT_" in response_str:
            return "ATT"
        elif "L2CAP" in response_str:
            return "L2CAP"
        elif "HCI" in response_str:
            return "HCI"
        elif operation in operation_to_layer:
            return operation_to_layer[operation]
        
        return "unknown"
    
    def _summarize_response(self, response_str):
        """Summarize response content"""
        if len(response_str) > 100:
            return response_str[:100] + "..."
        return response_str
    
    def _analyze_by_operation(self, response_str, operation):
        """Analyze based on operation type"""
        result = {
            "status": "unknown",
            "success_indicators": [],
            "warning_indicators": []
        }
        
        response_lower = response_str.lower()
        
        # Connection request analysis (key fix)
        if operation == "connection_request":
            return self._analyze_connection_response(response_str)
        
        # Scan request analysis
        elif operation == "scan_req":
            if "scanning" in response_lower or "advertising" in response_lower:
                result["status"] = "success"
                result["success_indicators"].append("Scan operation normal")
            elif "error" in response_lower or constant.ERROR:
                result["status"] = "error"
                result["warning_indicators"].append("Scan failed")
            else:
                result["status"] = "partial_success"
                result["warning_indicators"].append("Ambiguous scan response")
        
        # Length request analysis (focus attention)
        elif operation == "length_request":
            return self._analyze_length_response(response_str)
        
        # MTU request analysis
        elif operation == "mtu_request":
            if "mtu" in response_lower or "exchange" in response_lower:
                result["status"] = "success"
                result["success_indicators"].append("MTU exchange normal")
            elif response_str == "Empty" or not response_str.strip():
                result["status"] = "no_response"
                result["warning_indicators"].append("No response to MTU request")
            else:
                result["status"] = "unknown_response"
        
        # Pairing request analysis
        elif operation == "pairing_request":
            if "pairing" in response_lower or "security" in response_lower:
                result["status"] = "success"
                result["success_indicators"].append("Pairing process started")
            elif "reject" in response_lower or "invalid" in response_lower:
                result["status"] = "rejected"
                result["warning_indicators"].append("Pairing request rejected")
            else:
                result["status"] = "unknown_response"
        
        return result
    
    def _analyze_connection_response(self, response_str):
        """Intelligently analyze connection response (key function to fix misjudgment)"""
        result = {
            "status": "unknown",
            "success_indicators": [],
            "warning_indicators": []
        }
        
        # Check connection success indicators (key: LL_SLAVE_FEATURE_REQ is a sign of successful connection!)
        for indicator in self.CONNECTION_SUCCESS_INDICATORS:
            if indicator in response_str:
                result["status"] = "success"
                result["success_indicators"].append(f"Found connection success indicator: {indicator}")
                
                # Special note for LL_SLAVE_FEATURE_REQ
                if indicator == "LL_SLAVE_FEATURE_REQ":
                    result["success_indicators"].append("Link Layer Feature Request - Connection established successfully")
                
                break
        
        # If no success indicators found, check failure indicators
        if result["status"] == "unknown":
            for indicator in self.CONNECTION_FAILURE_INDICATORS:
                if indicator in response_str:
                    result["status"] = "error"
                    result["warning_indicators"].append(f"Found connection failure indicator: {indicator}")
                    break
        
        # If still unknown, check for LL layer PDU (may be successful connection with non-standard response)
        if result["status"] == "unknown":
            for ll_pdu in self.LL_CONNECTION_PDUS:
                if ll_pdu in response_str:
                    result["status"] = "success"
                    result["success_indicators"].append(f"Link Layer interaction: {ll_pdu} - {self.LL_CONNECTION_PDUS[ll_pdu]}")
                    result["warning_indicators"].append("Connection response format non-standard, but Link Layer interaction exists")
                    break
        
        # Finally, if response is empty or only basic framework
        if result["status"] == "unknown" and ("BTLE" in response_str or "BLE" in response_str):
            result["status"] = "partial_success"
            result["warning_indicators"].append("Received BLE frame packet, but no clear connection status")
        
        return result
    
    def _analyze_length_response(self, response_str):
        """Analyze length request response (focus on vulnerabilities)"""
        result = {
            "status": "unknown",
            "success_indicators": [],
            "warning_indicators": [],
            "vulnerability_hints": []
        }
        
        # Check for LL_LENGTH_RSP
        if "LL_LENGTH_RSP" in response_str:
            result["status"] = "success"
            result["success_indicators"].append("Received length response")
            
            # Check for abnormal values in response
            if "max_rx_bytes=0" in response_str or "max_tx_bytes=0" in response_str:
                result["warning_indicators"].append("Length response contains zero value - may not comply with specifications")
                result["vulnerability_hints"].append("SweynTooth-like vulnerability: zero length response")
        
        # Check for no response
        elif response_str == "Empty" or not response_str.strip():
            result["status"] = "no_response"
            result["warning_indicators"].append("No response to length request")
            result["vulnerability_hints"].append("Device may not handle abnormal length requests")
        
        # Check for other LL layer responses
        elif "LL_" in response_str:
            result["status"] = "partial_success"
            result["warning_indicators"].append("Received unexpected Link Layer response")
        
        # Check for errors
        elif "ERROR" in response_str or "error" in response_str:
            result["status"] = "error"
            result["warning_indicators"].append("Length request returned error")
        
        return result
    
    def _extract_error_codes(self, response_str):
        """Extract error codes"""
        error_details = []
        
        # Find hexadecimal error codes
        hex_pattern = r"0x[0-9a-fA-F]{2,4}"
        hex_matches = re.findall(hex_pattern, response_str)
        
        for hex_code in hex_matches:
            try:
                code_int = int(hex_code, 16)
                error_detail = {
                    "code": hex_code,
                    "decimal": code_int,
                    "description": self.HCI_ERROR_CODES.get(code_int, "Unknown error code")
                }
                error_details.append(error_detail)
            except ValueError:
                pass
        
        return error_details
    
    def _detect_vulnerability_hints(self, response_str, operation, context):
        """Detect vulnerability hints"""
        hints = []
        
        # Length request vulnerability detection
        if operation == "length_request":
            # No response may indicate device crash or state machine freeze
            if response_str == "Empty" or not response_str.strip():
                hints.append("Device has no response to abnormal length request - may trigger SweynTooth vulnerability")
            
            # Zero value length response
            if "max_rx_bytes=0" in response_str or "max_tx_bytes=0" in response_str:
                hints.append("Device accepts zero value length parameters - potential protocol stack vulnerability")
        
        # Abnormal connection status
        if "connection" in operation.lower() and "LL_TERMINATE_IND" in response_str:
            if context and "attack" in context:
                hints.append("Abnormal connection termination after attack - may trigger denial of service")
        
        # Abnormal state machine behavior
        if "LL_SLAVE_FEATURE_REQ" in response_str and "length_request" in operation:
            hints.append("Received feature request after length request - state machine may be abnormal")
        
        return hints
    
    def _determine_final_status(self, analysis):
        """Determine final status"""
        if analysis.get("is_error"):
            return "error"
        
        if analysis.get("status") in ["success", "partial_success"]:
            return analysis["status"]
        
        if analysis.get("success_indicators"):
            return "success"
        
        if analysis.get("warning_indicators"):
            return "warning"
        
        return "unknown"
    
    def _suggest_action(self, analysis):
        """Suggest action based on analysis results"""
        status = analysis.get("status", "unknown")
        operation = analysis.get("operation", "")
        
        suggestions = {
            "success": "Proceed to next operation",
            "partial_success": "Observe device behavior, consider retrying",
            "error": "Check device status and connection parameters",
            "no_response": "Wait for device recovery or restart device",
            "unknown": "Further analysis required"
        }
        
        # Operation-specific suggestions
        if operation == "connection_request" and status == "error":
            return "Check if device is in advertising state, adjust scan parameters"
        
        if "length_request" in operation and status == "no_response":
            return "Device may be sensitive to abnormal length requests, try testing with normal values"
        
        return suggestions.get(status, "No suggestions")
    
    def print_analysis(self, analysis, verbose=False):
        """Print analysis results"""
        status = analysis.get("status", "unknown")
        operation = analysis.get("operation", "unknown")
        
        # Status colors
        status_colors = {
            "success": Fore.GREEN,
            "partial_success": Fore.YELLOW,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "no_response": Fore.MAGENTA,
            "unknown": Fore.CYAN
        }
        
        color = status_colors.get(status, Fore.WHITE)
        
        print(f"\n{'='*60}")
        print(f"Intelligent Analysis - {operation}")
        print(f"{'='*60}")
        
        print(f"Status: {color}{status}{Style.RESET_ALL}")
        print(f"Protocol Layer: {analysis.get('protocol_layer', 'unknown')}")
        
        # Success indicators
        if analysis.get("success_indicators"):
            print(f"\n{Fore.GREEN}Success Indicators:{Style.RESET_ALL}")
            for indicator in analysis["success_indicators"]:
                print(f"  ✓ {indicator}")
        
        # Warning indicators
        if analysis.get("warning_indicators"):
            print(f"\n{Fore.YELLOW}Warning Indicators:{Style.RESET_ALL}")
            for indicator in analysis["warning_indicators"]:
                print(f"  ⚠ {indicator}")
        
        # Error details
        if analysis.get("error_details"):
            print(f"\n{Fore.RED}Error Details:{Style.RESET_ALL}")
            for error in analysis["error_details"]:
                if isinstance(error, dict):
                    print(f"  Code: {error.get('code', 'N/A')} - {error.get('description', 'N/A')}")
                else:
                    print(f"  {error}")
        
        # Vulnerability hints
        if analysis.get("vulnerability_hints"):
            print(f"\n{Fore.RED}Vulnerability Hints:{Style.RESET_ALL}")
            for hint in analysis["vulnerability_hints"]:
                print(f"  ⚡ {hint}")
        
        # Recommended action
        if analysis.get("recommended_action"):
            print(f"\n{Fore.CYAN}Recommended Action:{Style.RESET_ALL}")
            print(f"  ➤ {analysis['recommended_action']}")
        
        # Detailed output
        if verbose:
            print(f"\n{Fore.CYAN}Raw Response:{Style.RESET_ALL}")
            print(f"  {analysis.get('raw_response', 'N/A')[:200]}")
        
        print(f"{'='*60}")
        
        # Return status code (for automated judgment)
        status_codes = {
            "success": 0,
            "partial_success": 1,
            "warning": 2,
            "error": 3,
            "no_response": 4,
            "unknown": 5
        }
        
        return status_codes.get(status, 5)


class SmartBLETester:
    """Intelligent BLE Tester - Includes PCAP saving functionality"""
    
    def __init__(self, serial_port, address):
        self.serial_port = serial_port
        self.address = address
        self.ble = None
        self.analyzer = IntelligentBLEResponseAnalyzer()
        self.connection_stats = {
            "total_attempts": 0,
            "successful": 0,
            "failed": 0,
            "avg_time": 0
        }
        self.test_start_time = None
        self.pcap_filename = None
        
    def initialize(self, max_retries=3):
        """Initialize BLE connection"""
        print(Fore.CYAN + "[Initialization] Creating BLE test object...")
        
        for attempt in range(1, max_retries + 1):
            try:
                self.ble = FuzzingBLESUL(self.serial_port, self.address)
                print(Fore.GREEN + f"  ✓ BLE test object created successfully (attempt {attempt})")
                self.test_start_time = datetime.datetime.now()
                return True
            except Exception as e:
                print(Fore.YELLOW + f"  Attempt {attempt}/{max_retries} failed: {e}")
                if attempt < max_retries:
                    time.sleep(1)
        
        print(Fore.RED + "  ✗ Failed to create BLE test object")
        return False
    
    def save_pcap(self, filename=None):
        """
        Save PCAP log file
        
        Args:
            filename: File name, auto-generated if None
            
        Returns:
            bool: Whether saving was successful
        """
        if filename is None:
            # Auto-generate filename
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ble_smart_test_{timestamp}"
        
        # Ensure filename ends with .pcap
        if not filename.endswith('.pcap'):
            filename += '.pcap'
        
        self.pcap_filename = filename
        
        print(Fore.CYAN + f"\n[Saving PCAP Log]...")
        
        try:
            self.ble.save_pcap(filename)
            print(Fore.GREEN + f"  ✓ PCAP log saved: {filename}")
            return True
        except Exception as e:
            print(Fore.RED + f"  ✗ Failed to save PCAP log: {e}")
            return False
    
    def get_estimated_file_size(self):
        """Estimate PCAP file size (simplified version)"""
        # This is a simplified estimate, actual size depends on number of captured packets
        return "Unknown"
    
    def smart_connection_test(self, max_retries=7):
        """
        Intelligent connection test
        Fixes connection misjudgment issues
        """
        print(Fore.CYAN + "\n[Intelligent Connection Test]")
        print(f"  Target device: {self.address}")
        print(f"  Maximum retries: {max_retries}")
        
        for attempt in range(1, max_retries + 1):
            print(f"\n  Connection attempt {attempt}/{max_retries}:")
            
            try:
                # Send connection request
                start_time = time.time()
                response = self.ble.connection_request()
                elapsed_time = time.time() - start_time
                
                # Intelligently analyze response
                analysis = self.analyzer.intelligent_analyze_response(
                    response, 
                    "connection_request",
                    f"attempt_{attempt}"
                )
                
                # Print analysis results
                status_code = self.analyzer.print_analysis(analysis, verbose=True)
                
                # Update statistics
                self.connection_stats["total_attempts"] += 1
                
                if status_code <= 1:  # success or partial_success
                    self.connection_stats["successful"] += 1
                    print(Fore.GREEN + f"    ✓ Connection successful (time elapsed: {elapsed_time:.2f}s)")
                    
                    # Wait for stability
                    time.sleep(0.5)
                    return True, response, analysis
                else:
                    self.connection_stats["failed"] += 1
                    print(Fore.YELLOW + f"    ⚠ Connection has issues")
                
            except Exception as e:
                print(Fore.RED + f"    Connection exception: {e}")
                self.connection_stats["failed"] += 1
            
            # Wait for retry if not last attempt
            if attempt < max_retries:
                print("    Waiting 2 seconds before retry...")
                time.sleep(2)
        
        # Calculate average time
        if self.connection_stats["total_attempts"] > 0:
            self.connection_stats["avg_time"] = elapsed_time
        
        print(Fore.RED + f"\n    ✗ Connection test failed: {self.connection_stats['successful']}/{self.connection_stats['total_attempts']} successful")
        return False, None, None
    
    def test_length_vulnerability(self, max_rx_bytes=0):
        """
        Test length vulnerability (fixed version)
        """
        print(Fore.CYAN + "\n[Length Vulnerability Test]")
        print(f"  Test parameter: max_rx_bytes = {max_rx_bytes}")
        print(Fore.YELLOW + "  Note: Zero value may trigger SweynTooth-like vulnerabilities")
        
        # Phase 1: Establish connection
        print("\n  Phase 1: Establishing connection...")
        connected, connect_response, connect_analysis = self.smart_connection_test(max_retries=7)
        
        if not connected:
            print(Fore.RED + "    ✗ Cannot establish connection, test aborted")
            return {
                "test": "length_vulnerability",
                "max_rx_bytes": max_rx_bytes,
                "result": "failed_pre_connection",
                "details": "Cannot establish initial connection"
            }
        
        # Phase 2: Send abnormal length request
        print(f"\n  Phase 2: Sending LL_LENGTH_REQ (max_rx_bytes={max_rx_bytes})...")
        
        try:
            param = FuzzedParam("max_rx_bytes", max_rx_bytes)
            start_time = time.time()
            response = self.ble.length_request_fuzzed(param)
            elapsed_time = time.time() - start_time
            
            # Analyze length response
            analysis = self.analyzer.intelligent_analyze_response(
                response,
                "length_request",
                f"attack_max_rx_{max_rx_bytes}"
            )
            
            status_code = self.analyzer.print_analysis(analysis, verbose=True)
            print(f"    Request time elapsed: {elapsed_time:.2f}s")
            
            # Wait to observe device behavior
            print("    Waiting 3 seconds to observe device behavior...")
            time.sleep(3)
            
            result = {
                "test": "length_vulnerability",
                "max_rx_bytes": max_rx_bytes,
                "request_time": elapsed_time,
                "response_analysis": analysis,
                "vulnerability_indicated": len(analysis.get("vulnerability_hints", [])) > 0
            }
            
        except Exception as e:
            print(Fore.RED + f"    Length request exception: {e}")
            result = {
                "test": "length_vulnerability",
                "max_rx_bytes": max_rx_bytes,
                "result": "exception",
                "error": str(e)
            }
        
        # Phase 3: Test connection recovery capability
        print("\n  Phase 3: Testing connection recovery capability...")
        
        recovery_results = []
        for i in range(7):
            print(f"    Recovery test {i+1}/7...")
            time.sleep(4)
            
            try:
                # Attempt reconnection
                reconnect_response = self.ble.connection_request()
                reconnect_analysis = self.analyzer.intelligent_analyze_response(
                    reconnect_response,
                    "post_attack_connection",
                    f"recovery_attempt_{i+1}"
                )
                
                status = "success" if reconnect_analysis.get("status") == "success" else "failed"
                recovery_results.append({
                    "attempt": i+1,
                    "status": status,
                    "analysis": reconnect_analysis
                })
                
                # Disconnect for next test
                if status == "success":
                    self.ble.termination_indication()
                    time.sleep(0.5)
                
                print(f"      {Fore.GREEN if status == 'success' else Fore.RED}{status}{Style.RESET_ALL}")
                
            except Exception as e:
                print(Fore.RED + f"      Recovery test exception: {e}")
                recovery_results.append({
                    "attempt": i+1,
                    "status": "exception",
                    "error": str(e)
                })
        
        result["recovery_tests"] = recovery_results
        
        # Judge overall result
        successful_recoveries = sum(1 for r in recovery_results if r.get("status") == "success")
        
        if successful_recoveries == 0:
            result["overall_result"] = "device_crashed"
            result["vulnerability"] = "Confirmed - Denial of Service vulnerability"
        elif successful_recoveries < len(recovery_results):
            result["overall_result"] = "partial_recovery"
            result["vulnerability"] = "Suspected - Partial Denial of Service"
        else:
            result["overall_result"] = "full_recovery"
            result["vulnerability"] = "No vulnerability"
        
        return result
    
    def comprehensive_vulnerability_test(self, save_pcap=True):
        """Comprehensive vulnerability test"""
        print(Fore.CYAN + "\n" + "="*70)
        print(Fore.CYAN + "Comprehensive Vulnerability Test Suite")
        print(Fore.CYAN + "="*70)
        
        test_results = []
        
        # 1. Length vulnerability test
        print(Fore.YELLOW + "\n[Test 1] Zero Value Length Attack (SweynTooth-like)")
        result1 = self.test_length_vulnerability(max_rx_bytes=0)
        test_results.append(result1)
        
        # Short rest
        time.sleep(5)
        
        # 2. Extra large value length test
        print(Fore.YELLOW + "\n[Test 2] Extra Large Value Length Attack")
        result2 = self.test_length_vulnerability(max_rx_bytes=3000)
        test_results.append(result2)
        
        # Short rest
        time.sleep(5)
        
        # 3. Normal value length test (control)
        print(Fore.YELLOW + "\n[Test 3] Normal Value Length Test (Control)")
        result3 = self.test_length_vulnerability(max_rx_bytes=251)  # BLE standard maximum value
        test_results.append(result3)
        
        # Save PCAP
        if save_pcap:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_filename = f"ble_smart_test_{timestamp}"
            self.save_pcap(pcap_filename)
        
        # Analyze results
        self.analyze_test_results(test_results)
        
        return test_results
    
    def analyze_test_results(self, test_results):
        """Analyze test results"""
        print(Fore.CYAN + "\n" + "="*70)
        print(Fore.CYAN + "Vulnerability Test Result Analysis")
        print(Fore.CYAN + "="*70)
        
        vulnerabilities_found = []
        warnings = []
        
        for result in test_results:
            test_name = result.get("test", "unknown")
            max_rx_bytes = result.get("max_rx_bytes", "N/A")
            overall_result = result.get("overall_result", "unknown")
            
            print(f"\n{Fore.YELLOW}Test: {test_name} (max_rx_bytes={max_rx_bytes})")
            print(f"Result: {overall_result}")
            
            if "vulnerability" in result:
                vuln_status = result["vulnerability"]
                if "Confirmed" in vuln_status or "Suspected" in vuln_status:
                    print(Fore.RED + f"Vulnerability status: {vuln_status}")
                    vulnerabilities_found.append({
                        "test": test_name,
                        "max_rx_bytes": max_rx_bytes,
                        "status": vuln_status
                    })
                else:
                    print(Fore.GREEN + f"Vulnerability status: {vuln_status}")
            
            # Recovery test details
            if "recovery_tests" in result:
                recovery_tests = result["recovery_tests"]
                successful = sum(1 for r in recovery_tests if r.get("status") == "success")
                print(f"Recovery tests: {successful}/{len(recovery_tests)} successful")
                
                if successful == 0:
                    warnings.append(f"{test_name}: Device completely unresponsive")
                elif successful < len(recovery_tests):
                    warnings.append(f"{test_name}: Device partially recovered")
        
        # Overall assessment
        print(Fore.CYAN + "\n" + "="*70)
        print(Fore.CYAN + "Security Assessment")
        print(Fore.CYAN + "="*70)
        
        if vulnerabilities_found:
            print(Fore.RED + "✗ Security vulnerabilities found")
            print("\nVulnerability details:")
            for vuln in vulnerabilities_found:
                print(f"  - {vuln['test']} (max_rx_bytes={vuln['max_rx_bytes']}): {vuln['status']}")
            
            print(Fore.YELLOW + "\nImpact:")
            print("  • Attackers can cause device denial of service")
            print("  • Device may require manual restart")
            print("  • May affect device reliability and user experience")
            
            print(Fore.GREEN + "\nRecommended remediation measures:")
            print("  1. Validate Link Layer length fields, reject zero or out-of-range values")
            print("  2. Add defensive state machine handling for unexpected length transactions")
            print("  3. Apply protocol stack updates from device manufacturer")
            print("  4. Implement automatic recovery mechanism for Link Layer failures")
            
        elif warnings:
            print(Fore.YELLOW + "⚠ Abnormal behavior found")
            print("\nAbnormal details:")
            for warning in warnings:
                print(f"  • {warning}")
            
            print(Fore.CYAN + "\nRecommendations:")
            print("  • Conduct further testing to confirm if it is a vulnerability")
            print("  • Monitor device behavior under abnormal conditions")
            print("  • Consider updating device firmware")
            
        else:
            print(Fore.GREEN + "✓ Device security is good")
            print("\nDevice has good resistance to abnormal inputs tested")
            print("Regular security testing is recommended to ensure security")
        
        # Connection statistics
        print(Fore.CYAN + "\n" + "="*70)
        print(Fore.CYAN + "Connection Statistics")
        print(Fore.CYAN + "="*70)
        print(f"Total connection attempts: {self.connection_stats['total_attempts']}")
        print(f"Successful connections: {self.connection_stats['successful']}")
        print(f"Failed connections: {self.connection_stats['failed']}")
        
        if self.connection_stats['total_attempts'] > 0:
            success_rate = self.connection_stats['successful'] / self.connection_stats['total_attempts']
            print(f"Connection success rate: {success_rate:.1%}")
        
        # PCAP file information
        if self.pcap_filename:
            print(Fore.CYAN + "\n" + "="*70)
            print(Fore.CYAN + "Log Files")
            print(Fore.CYAN + "="*70)
            print(f"PCAP log: {self.pcap_filename}")
        
        # Save report
        self.save_test_report(test_results)
    
    def save_test_report(self, test_results):
        """Save test report"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"ble_security_report_{timestamp}.txt"
        
        try:
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write("="*70 + "\n")
                f.write("BLE Device Security Test Report\n")
                f.write("="*70 + "\n\n")
                
                f.write(f"Test time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Device address: {self.address}\n")
                f.write(f"Serial port: {self.serial_port}\n\n")
                
                if self.pcap_filename:
                    f.write(f"PCAP log file: {self.pcap_filename}\n\n")
                
                f.write("Connection statistics:\n")
                f.write(f"  Total connection attempts: {self.connection_stats['total_attempts']}\n")
                f.write(f"  Successful connections: {self.connection_stats['successful']}\n")
                f.write(f"  Failed connections: {self.connection_stats['failed']}\n")
                
                if self.connection_stats['total_attempts'] > 0:
                    success_rate = self.connection_stats['successful'] / self.connection_stats['total_attempts']
                    f.write(f"  Connection success rate: {success_rate:.1%}\n\n")
                
                f.write("Test results:\n")
                for result in test_results:
                    f.write(f"\n  Test: {result.get('test', 'N/A')}\n")
                    f.write(f"  Parameter: max_rx_bytes={result.get('max_rx_bytes', 'N/A')}\n")
                    f.write(f"  Result: {result.get('overall_result', 'N/A')}\n")
                    
                    if 'vulnerability' in result:
                        f.write(f"  Vulnerability status: {result['vulnerability']}\n")
                    
                    if 'recovery_tests' in result:
                        recovery_tests = result['recovery_tests']
                        successful = sum(1 for r in recovery_tests if r.get('status') == 'success')
                        f.write(f"  Recovery tests: {successful}/{len(recovery_tests)} successful\n")
                
                f.write("\n" + "="*70 + "\n")
                f.write("Report End\n")
                f.write("="*70 + "\n")
            
            print(Fore.GREEN + f"\n✓ Test report saved: {report_filename}")
            
        except Exception as e:
            print(Fore.RED + f"✗ Failed to save report: {e}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python ble_smart_tester.py <serial_port> <address> [pcap_filename]")
        print("Example: python ble_smart_tester.py COM74 24:B2:31:D1:81:30 [output.pcap]")
        sys.exit(1)
    
    serial_port = sys.argv[1]
    address = sys.argv[2].upper().replace('-', ':')
    
    # Get optional PCAP filename
    if len(sys.argv) >= 4:
        pcap_filename = sys.argv[3]
    else:
        # Use default filename (with timestamp)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_filename = f'ble_smart_test_{timestamp}'
    
    print(Fore.CYAN + "="*70)
    print(Fore.CYAN + "BLE Device Intelligent Security Tester (with PCAP Saving)")
    print(Fore.CYAN + "="*70)
    print(f"Device address: {address}")
    print(f"Serial port: {serial_port}")
    print(f"PCAP file: {pcap_filename}")
    print(Fore.YELLOW + "Note: This version fixes connection response misjudgment issues")
    
    # Create tester
    tester = SmartBLETester(serial_port, address)
    
    if not tester.initialize():
        print(Fore.RED + "Initialization failed, program exiting")
        sys.exit(1)
    
    try:
        # Run comprehensive vulnerability test (auto-save PCAP)
        results = tester.comprehensive_vulnerability_test(save_pcap=True)
        
        print(Fore.CYAN + "\n" + "="*70)
        print(Fore.CYAN + "Test Completed")
        print(Fore.CYAN + "="*70)
        
        if tester.pcap_filename:
            print(f"PCAP log saved: {tester.pcap_filename}")
        
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nTest interrupted by user")
        
        # Save PCAP even when interrupted
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_filename = f"ble_smart_test_interrupted_{timestamp}"
            tester.save_pcap(pcap_filename)
            print(Fore.GREEN + f"PCAP log before interruption saved: {pcap_filename}")
        except:
            pass
            
    except Exception as e:
        print(Fore.RED + f"\nException occurred during test: {e}")
        import traceback
        traceback.print_exc()
        
        # Attempt to save PCAP even on exception
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_filename = f"ble_smart_test_error_{timestamp}"
            tester.save_pcap(pcap_filename)
            print(Fore.GREEN + f"PCAP log before exception saved: {pcap_filename}")
        except:
            pass
        
    finally:
        # Attempt to disconnect
        try:
            tester.ble.termination_indication()
            print(Fore.GREEN + "Disconnected successfully")
        except:
            pass


if __name__ == "__main__":
    main()
