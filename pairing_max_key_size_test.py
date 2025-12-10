#!/usr/bin/env python3
"""
Usage: python pairing_max_key_size_test_retry.py <serial port> <BLE address> [pcap filename]
Example: python pairing_max_key_size_test_retry.py COM74 24:B2:31:D1:81:30
"""

import sys
import time
import platform
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Import required modules
try:
    import constant
    from fuzzing.FuzzingBLESUL import FuzzingBLESUL, FuzzedParam
    MODULES_LOADED = True
except ImportError as e:
    print(Fore.RED + f"Failed to import modules: {e}")
    print(Fore.YELLOW + "Please ensure you are running in the correct project directory")
    MODULES_LOADED = False

class EnhancedBLEPairingTester:
    """Enhanced BLE Pairing Tester with retry mechanism"""
    
    def __init__(self, serial_port, ble_address, debug=True):
        """
        Initialize the tester
        
        Args:
            serial_port: Serial port device path
            ble_address: BLE device address
            debug: Whether to enable debug output
        """
        if not MODULES_LOADED:
            raise ImportError("Required modules not loaded, cannot create tester")
            
        self.serial_port = serial_port
        self.ble_address = ble_address
        self.debug = debug
        self.ble_sul = None
        self.initialize_connection()
    
    def initialize_connection(self):
        """Initialize BLE connection"""
        print(Fore.CYAN + "[Initialization] Creating BLE test object...")
        
        # Fix serial port name
        fixed_port = self._fix_serial_port()
        print(f"  Serial Port: {self.serial_port} -> {fixed_port}")
        print(f"  Address: {self.ble_address}")
        
        try:
            self.ble_sul = FuzzingBLESUL(fixed_port, self.ble_address)
            print(Fore.GREEN + "  ✓ BLE test object created successfully")
                
        except Exception as e:
            print(Fore.RED + f"  ✗ Creation failed: {e}")
            raise
    
    def _fix_serial_port(self):
        """Fix serial port device name"""
        system = platform.system()
        port = self.serial_port
        
        if system == "Windows":
            if port.isdigit():
                return f"COM{port}"
            elif not port.upper().startswith("COM"):
                return f"COM{port}"
            return port.upper()
        elif system == "Linux":
            if port.upper().startswith("COM"):
                com_num = ''.join(filter(str.isdigit, port))
                return f"/dev/ttyACM{com_num}"
            return port
        else:
            return port
    
    def robust_scan(self, max_retries=7, retry_delay=1.0):
        """
        Robust scanning with retries
        
        Args:
            max_retries: Maximum number of retries
            retry_delay: Retry delay time (seconds)
            
        Returns:
            tuple: (success status, scan result)
        """
        for attempt in range(1, max_retries + 1):
            print(f"    Scan attempt {attempt}/{max_retries}...", end='', flush=True)
            
            try:
                scan_result = self.ble_sul.scan_req()
                
                if scan_result == constant.ERROR:
                    print(Fore.YELLOW + "failed")
                    if attempt < max_retries:
                        time.sleep(retry_delay)
                    continue
                
                print(Fore.GREEN + "success")
                return True, scan_result
                
            except Exception as e:
                print(Fore.RED + f"exception: {e}")
                if attempt < max_retries:
                    time.sleep(retry_delay)
        
        return False, None
    
    def robust_connect(self, max_retries=7, retry_delay=1.0):
        """
        Robust connection with retries
        
        Args:
            max_retries: Maximum number of retries
            retry_delay: Retry delay time (seconds)
            
        Returns:
            tuple: (success status, connection result)
        """
        for attempt in range(1, max_retries + 1):
            print(f"    Connection attempt {attempt}/{max_retries}...", end='', flush=True)
            
            try:
                connect_result = self.ble_sul.connection_request()
                
                if connect_result == constant.ERROR:
                    print(Fore.YELLOW + "failed")
                    if attempt < max_retries:
                        time.sleep(retry_delay)
                    continue
                
                print(Fore.GREEN + "success")
                return True, connect_result
                
            except Exception as e:
                print(Fore.RED + f"exception: {e}")
                if attempt < max_retries:
                    time.sleep(retry_delay)
        
        return False, None
    
    def robust_pairing_test(self, key_size, max_scan_retries=7, max_connect_retries=7):
        """
        Robust pairing test with complete retry mechanism
        
        Args:
            key_size: Key size to test
            max_scan_retries: Maximum scan retries
            max_connect_retries: Maximum connection retries
            
        Returns:
            tuple: (whether key size is accepted, test details)
        """
        print(f"  [Test] Key size: {key_size}")
        
        # 1. Scan device (with retries)
        print("    Scanning device...")
        scan_success, scan_result = self.robust_scan(max_retries=max_scan_retries)
        
        if not scan_success:
            print(Fore.RED + f"    ✗ Scan failed, skipping key size {key_size}")
            return False, {"scan_success": False, "connect_success": False}
        
        # 2. Connect to device (with retries)
        print("    Connecting to device...")
        connect_success, connect_result = self.robust_connect(max_retries=max_connect_retries)
        
        if not connect_success:
            print(Fore.RED + f"    ✗ Connection failed, skipping key size {key_size}")
            return False, {"scan_success": True, "connect_success": False}
        
        # 3. Wait for stable connection
        print("    Waiting for stable connection...", end='', flush=True)
        time.sleep(0.5)
        print(Fore.GREEN + "completed")
        
        # 4. Send pairing request
        pairing_accepted = False
        pairing_response = None
        
        try:
            print("    Sending pairing request...", end='', flush=True)
            key_size_param = FuzzedParam("max_key_size", key_size)
            pairing_response = self.ble_sul.pairing_request_fuzzed(key_size_param)
            
            # Wait for response
            wait_time = 2.0
            time.sleep(wait_time)
            
            print(Fore.GREEN + "sent successfully")
            
            # 5. Check response
            print("    Checking response...", end='', flush=True)
            
            if pairing_response is None:
                print(Fore.YELLOW + "no response object")
            else:
                response_str = str(pairing_response)
                print(f"response: {response_str[:100]}")
                
                # Check if contains pairing response
                if isinstance(pairing_response, str):
                    if "SM_Pairing_Response" in pairing_response:
                        pairing_accepted = True
                    elif any(keyword in pairing_response for keyword in ["Pairing", "pairing", "Security"]):
                        # Contains pairing-related keywords
                        print(Fore.CYAN + "contains pairing-related response")
                        pairing_accepted = True
                else:
                    # Non-string type, check string representation
                    resp_text = str(pairing_response)
                    if "SM_Pairing_Response" in resp_text or "Pairing_Response" in resp_text:
                        pairing_accepted = True
        
        except Exception as e:
            print(Fore.RED + f"Pairing request exception: {e}")
        
        finally:
            # 6. Disconnect
            print("    Disconnecting...", end='', flush=True)
            try:
                self.ble_sul.termination_indication()
                time.sleep(0.3)  # Wait for disconnection completion
                print(Fore.GREEN + "completed")
            except Exception as e:
                print(Fore.YELLOW + f"Disconnection exception: {e}")
        
        return pairing_accepted, {
            "scan_success": True,
            "connect_success": True,
            "pairing_response": pairing_response
        }
    
    def run_comprehensive_pairing_test(self, start_key_size=16, end_key_size=7):
        """
        Comprehensive pairing test with complete retry and statistics
        
        Args:
            start_key_size: Starting key size
            end_key_size: Ending key size
            
        Returns:
            tuple: (list of accepted key sizes, test statistics)
        """
        print(Fore.CYAN + "\n[Pairing Test] Starting key size fuzzing test...")
        print(f"  Test range: Key size {start_key_size} -> {end_key_size}")
        print(Fore.YELLOW + "  Note: BLE standard requires minimum key size of 7 bytes")
        print(Fore.YELLOW + "  Each key size test includes scanning (7 retries) and connection (7 retries)")
        
        accepted_key_sizes = []
        test_stats = {
            'total_tests': 0,
            'successful_tests': 0,
            'failed_tests': 0,
            'scan_failures': 0,
            'connect_failures': 0,
            'pairing_rejections': 0,
            'no_response': 0
        }
        
        # Ensure start_key_size >= end_key_size
        if start_key_size < end_key_size:
            start_key_size, end_key_size = end_key_size, start_key_size
        
        current_key_size = start_key_size
        
        while current_key_size >= end_key_size:
            test_stats['total_tests'] += 1
            
            print(f"\n  [Test {test_stats['total_tests']}/{start_key_size-end_key_size+1}]")
            
            # Execute robust pairing test
            pairing_accepted, test_details = self.robust_pairing_test(
                current_key_size,
                max_scan_retries=7,
                max_connect_retries=7
            )
            
            # Update statistics
            if not test_details.get("scan_success"):
                test_stats['scan_failures'] += 1
                test_stats['failed_tests'] += 1
                print(Fore.RED + f"    ✗ Skipping key size {current_key_size} (scan failed)")
            elif not test_details.get("connect_success"):
                test_stats['connect_failures'] += 1
                test_stats['failed_tests'] += 1
                print(Fore.RED + f"    ✗ Skipping key size {current_key_size} (connection failed)")
            elif pairing_accepted:
                accepted_key_sizes.append(current_key_size)
                test_stats['successful_tests'] += 1
                print(Fore.GREEN + f"    ✓ Device accepted key size {current_key_size}")
            else:
                test_stats['pairing_rejections'] += 1
                test_stats['failed_tests'] += 1
                print(Fore.YELLOW + f"    ✗ Device rejected key size {current_key_size}")
            
            # Short rest to avoid device overload
            if current_key_size > end_key_size:
                print("    Waiting 2 seconds before next test...")
                time.sleep(2)
            
            current_key_size -= 1
        
        return accepted_key_sizes, test_stats
    
    def test_device_availability(self, max_attempts=5):
        """
        Test device availability with retries
        
        Args:
            max_attempts: Maximum number of attempts
            
        Returns:
            tuple: (availability status, statistics)
        """
        print(Fore.CYAN + "\n[Device Availability Test] Verifying device reachability...")
        print(Fore.YELLOW + f"  Will attempt to scan and connect to device, maximum {max_attempts} times")
        
        successful_scans = 0
        successful_connects = 0
        
        for attempt in range(1, max_attempts + 1):
            print(f"\n  Attempt {attempt}/{max_attempts}:")
            
            # Scan
            print("    Scanning...", end='', flush=True)
            scan_success, scan_result = self.robust_scan(max_retries=3)
            
            if scan_success:
                successful_scans += 1
                print(Fore.GREEN + "success")
                
                # Connect
                print("    Connecting...", end='', flush=True)
                connect_success, connect_result = self.robust_connect(max_retries=3)
                
                if connect_success:
                    successful_connects += 1
                    print(Fore.GREEN + "success")
                    
                    # Disconnect
                    print("    Disconnecting...", end='', flush=True)
                    try:
                        self.ble_sul.termination_indication()
                        time.sleep(0.3)
                        print(Fore.GREEN + "completed")
                    except Exception as e:
                        print(Fore.YELLOW + f"exception: {e}")
                else:
                    print(Fore.YELLOW + "failed")
            else:
                print(Fore.YELLOW + "failed")
            
            # Wait if not last attempt
            if attempt < max_attempts:
                time.sleep(1)
        
        # Calculate success rates
        scan_success_rate = successful_scans / max_attempts
        connect_success_rate = successful_connects / successful_scans if successful_scans > 0 else 0
        
        print(Fore.CYAN + f"\n  Availability statistics:")
        print(f"    Scan success rate: {scan_success_rate:.0%} ({successful_scans}/{max_attempts})")
        print(f"    Connection success rate: {connect_success_rate:.0%} ({successful_connects}/{successful_scans if successful_scans > 0 else 'N/A'})")
        
        # Determine device availability
        device_available = scan_success_rate >= 0.4 and connect_success_rate >= 0.5
        
        if device_available:
            print(Fore.GREEN + f"  ✓ Device is available, can continue testing")
        else:
            print(Fore.YELLOW + f"  ⚠ Device availability is low, tests may fail")
            
            if scan_success_rate < 0.4:
                print(Fore.YELLOW + "    Low scan success rate, possible reasons:")
                print("      1. Device is too far away")
                print("      2. Device broadcast interval is too long")
                print("      3. Device is in deep sleep mode")
            
            if connect_success_rate < 0.5:
                print(Fore.YELLOW + "    Low connection success rate, possible reasons:")
                print("      1. Device has reached maximum connection limit")
                print("      2. Device security policy restrictions")
                print("      3. Insufficient device resources")
        
        return device_available, {
            "scan_success_rate": scan_success_rate,
            "connect_success_rate": connect_success_rate,
            "successful_scans": successful_scans,
            "successful_connects": successful_connects
        }
    
    def save_pcap(self, filename):
        """Save PCAP log file"""
        try:
            self.ble_sul.save_pcap(filename)
            print(Fore.GREEN + f"  ✓ Log saved: {filename}")
            return True
        except Exception as e:
            print(Fore.YELLOW + f"  ⚠ Failed to save log: {e}")
            return False

def main():
    """Main function"""
    # Parameter check
    if len(sys.argv) < 3:
        print(Fore.RED + "Insufficient parameters")
        print(Fore.CYAN + "Usage: python pairing_max_key_size_test_retry.py <serial port> <BLE address> [pcap filename]")
        print(Fore.CYAN + "Example: python pairing_max_key_size_test_retry.py COM74 24:B2:31:D1:81:30")
        sys.exit(1)
    
    # Check if modules loaded successfully
    if not MODULES_LOADED:
        print(Fore.RED + "Failed to load required modules, exiting program")
        sys.exit(1)
    
    # Parse parameters
    serial_port = sys.argv[1]
    ble_address = sys.argv[2].upper().replace('-', ':')
    
    if len(sys.argv) >= 4:
        pcap_filename = sys.argv[3]
        if not pcap_filename.endswith('.pcap'):
            pcap_filename += '.pcap'
    else:
        pcap_filename = f'pairing_test_{ble_address.replace(":", "_")}.pcap'
    
    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + "BLE Pairing Key Size Test - Enhanced Retry Version")
    print(Fore.CYAN + "=" * 60)
    print(Fore.YELLOW + "Note: This version adds retry mechanism for scanning and connection")
    print(Fore.YELLOW + "      Maximum 7 retries for scanning and 7 retries for connection")
    
    # Create tester
    try:
        tester = EnhancedBLEPairingTester(serial_port, ble_address, debug=True)
    except Exception as e:
        print(Fore.RED + f"Initialization failed: {e}")
        sys.exit(1)
    
    # Phase 1: Test device availability
    # print(Fore.CYAN + "\n[Phase 1] Device Availability Test...")
    # device_available, availability_stats = tester.test_device_availability(max_attempts=5)
    
    # if not device_available:
    #     print(Fore.YELLOW + "\n⚠ Device availability is low")
    #     print(Fore.YELLOW + "Continuing test may result in many failures")
        
    #     response = input(Fore.YELLOW + "\nContinue with test? (y/n): ").strip().lower()
    #     if response != 'y':
    #         print(Fore.CYAN + "Test aborted")
    #         sys.exit(0)
        
    #     print(Fore.YELLOW + "Continuing test with expected low success rate...")
    
    # Phase 2: Execute pairing test
    print(Fore.CYAN + "\n[Phase 2] Key Size Range Test (16->7)...")
    accepted_sizes, stats = tester.run_comprehensive_pairing_test(start_key_size=16, end_key_size=7)
    
    # Output detailed statistics
    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.CYAN + "[Test Statistics]")
    print(Fore.CYAN + "=" * 60)
    print(f"  Total tests: {stats['total_tests']}")
    print(f"  Successful tests: {stats['successful_tests']}")
    print(f"  Failed tests: {stats['failed_tests']}")
    print(f"  Scan failures: {stats['scan_failures']}")
    print(f"  Connection failures: {stats['connect_failures']}")
    print(f"  Pairing rejections: {stats['pairing_rejections']}")
    print(f"  No response: {stats['no_response']}")
    
    if stats['total_tests'] > 0:
        success_rate = stats['successful_tests'] / stats['total_tests']
        print(f"  Success rate: {success_rate:.0%}")
    
    # Analyze test results
    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.CYAN + "[Result Analysis]")
    print(Fore.CYAN + "=" * 60)
    
    if len(accepted_sizes) == 0:
        print(Fore.RED + "✗ Device did not accept pairing requests for any key sizes")
        print(Fore.YELLOW + "  Possible reasons:")
        print("    1. Device may not support pairing")
        print("    2. Incorrect pairing request format")
        print("    3. Device security policy restricts pairing")
        print("    4. User confirmation required but not provided")
        print("    5. Device cannot maintain stable connection")
    else:
        accepted_sizes.sort()
        print(Fore.GREEN + f"✓ Key sizes accepted by device: {accepted_sizes}")
        
        if len(accepted_sizes) > 1:
            print(Fore.YELLOW + f"  Device accepted {len(accepted_sizes)} different key sizes")
            print(Fore.YELLOW + f"  Minimum accepted: {min(accepted_sizes)}, Maximum accepted: {max(accepted_sizes)}")
            
            # Check for non-standard key sizes
            non_standard = [size for size in accepted_sizes if size < 7 or size > 16]
            if non_standard:
                print(Fore.RED + f"  ⚠ Warning: Device accepted non-standard key sizes: {non_standard}")
        else:
            print(Fore.YELLOW + f"  Device only accepted key size: {accepted_sizes[0]}")
    
    # Device status check
    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.CYAN + "[Final Status Check]")
    print(Fore.CYAN + "=" * 60)
    
    # Simple check if device still responds
    print("  Quick device status check...")
    try:
        scan_success, _ = tester.robust_scan(max_retries=3)
        if scan_success:
            print(Fore.GREEN + "  ✓ Device is still scannable")
            
            connect_success, _ = tester.robust_connect(max_retries=2)
            if connect_success:
                print(Fore.GREEN + "  ✓ Device is still connectable")
                
                # Disconnect
                try:
                    tester.ble_sul.termination_indication()
                except:
                    pass
            else:
                print(Fore.YELLOW + "  ⚠ Device is scannable but not connectable")
        else:
            print(Fore.RED + "  ✗ Device not scannable, may have crashed or unresponsive")
    except Exception as e:
        print(Fore.RED + f"  Status check exception: {e}")
    
    # Save log
    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.CYAN + "[Log Saving]")
    print(Fore.CYAN + "=" * 60)
    tester.save_pcap(pcap_filename)
    
    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.CYAN + "Test completed!")
    print(Fore.CYAN + "=" * 60)

if __name__ == "__main__":
    main()
