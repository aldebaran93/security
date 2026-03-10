"""
Complete py-uds + Vector CANoe/CAN Hardware Integration Example
UDS Diagnostic Communication (Read/Write Data, Security Access, Routine Control)
"""

import time
import logging
from typing import Optional, List, Dict, Any, Callable

# Core library imports
import can
import uds
from uds import UdsConnection, UdsError
from uds.transport import CanTransport
from uds.services import *


# ============================================================================
# Configuration Section - Modify for Your Environment
# ============================================================================

class VectorCanoeConfig:
    """Vector CANoe Configuration Parameters"""
    
    # Vector Interface Configuration
    INTERFACE = 'vector'           # Use Vector interface
    APP_NAME = 'CANoe'             # CANoe application name (match Vector config)
    CHANNEL = 0                     # CAN channel number (usually 0 or 1)
    BITRATE = 500000                # 500 kbps (standard CAN rate)
    
    # UDS Diagnostic Configuration
    REQUEST_ID = 0x7E0              # Diagnostic request ID (Tester -> ECU)
    RESPONSE_ID = 0x7E8              # Diagnostic response ID (ECU -> Tester)
    
    # Timeout Configuration (seconds)
    REQUEST_TIMEOUT = 3.0
    P2_TIMEOUT = 0.5                 # P2 timeout (ECU response time)
    P2_STAR_TIMEOUT = 2.0             # P2* timeout (long response time)


# ============================================================================
# UDS Connection Manager
# ============================================================================

class UdsVectorManager:
    """
    UDS with Vector CANoe Integration Manager
    Handles connection establishment, session management, security access
    """
    
    def __init__(self, config: VectorCanoeConfig):
        self.config = config
        self.can_bus: Optional[can.BusABC] = None
        self.uds_conn: Optional[UdsConnection] = None
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger('UdsVector')
        logger.setLevel(logging.INFO)
        
        # Console handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def connect(self) -> bool:
        """
        Establish connection to Vector CANoe/CAN hardware
        """
        try:
            self.logger.info("Connecting to Vector CAN interface...")
            
            # 1. Create python-can Vector bus
            self.can_bus = can.Bus(
                interface=self.config.INTERFACE,
                channel=self.config.CHANNEL,
                bitrate=self.config.BITRATE,
                app_name=self.config.APP_NAME,
                receive_own_messages=False
            )
            
            self.logger.info(f"CAN bus connected: {self.can_bus.channel_info}")
            
            # 2. Create ISO-TP transport layer (uses python-can-isotp internally)
            transport = CanTransport(
                can_bus=self.can_bus,
                tx_id=self.config.REQUEST_ID,
                rx_id=self.config.RESPONSE_ID,
                timeout=self.config.REQUEST_TIMEOUT
            )
            
            # 3. Create UDS connection
            self.uds_conn = UdsConnection(
                transport=transport,
                p2_timeout=self.config.P2_TIMEOUT,
                p2_star_timeout=self.config.P2_STAR_TIMEOUT
            )
            
            self.logger.info("UDS connection established successfully")
            self.logger.info(f"Request ID: 0x{self.config.REQUEST_ID:X}, Response ID: 0x{self.config.RESPONSE_ID:X}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Close connection"""
        if self.can_bus:
            self.can_bus.shutdown()
            self.logger.info("CAN connection closed")
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()


# ============================================================================
# UDS Diagnostic Operations
# ============================================================================

class UdsDiagnosticOperations:
    """UDS diagnostic operations wrapper class"""
    
    def __init__(self, uds_manager: UdsVectorManager):
        self.uds = uds_manager
        self.logger = uds_manager.logger
    
    # ------------------------------------------------------------------------
    # Diagnostic Session Control (0x10)
    # ------------------------------------------------------------------------
    
    def change_session(self, session_type: int) -> bool:
        """
        Switch diagnostic session
        
        Args:
            session_type: Session type
                0x01 - Default session
                0x02 - Programming session
                0x03 - Extended session
                0x04 - Security session
        """
        session_names = {
            0x01: "Default Session",
            0x02: "Programming Session", 
            0x03: "Extended Session",
            0x04: "Security Session"
        }
        
        session_name = session_names.get(session_type, f"Unknown(0x{session_type:02X})")
        
        try:
            self.logger.info(f"Switching to {session_name}...")
            
            # Send diagnostic session control request
            response = self.uds.uds_conn.send(
                DiagnosticSessionControl(session_type=session_type)
            )
            
            if response and response.service_id == 0x50:  # 0x50 = Session control positive response
                self.logger.info(f"✓ Successfully switched to {session_name}")
                return True
            else:
                self.logger.error(f"Session switch failed: {response}")
                return False
                
        except UdsError as e:
            self.logger.error(f"Session switch error: {e}")
            return False
    
    # ------------------------------------------------------------------------
    # Security Access (0x27)
    # ------------------------------------------------------------------------
    
    def security_access(self, level: int, seed_key_func: Callable[[bytes], bytes]) -> bool:
        """
        Perform security access (seed and key)
        
        Args:
            level: Security level
                0x01/0x02 - Level 1
                0x03/0x04 - Level 2
                0x05/0x06 - Level 3
            seed_key_func: Callback function to calculate key from seed
        """
        try:
            self.logger.info(f"Performing security access (Level 0x{level:02X})...")
            
            # 1. Request seed (sub-function = level, odd number)
            seed_response = self.uds.uds_conn.send(
                SecurityAccess(level)
            )
            
            if not seed_response or seed_response.service_id != 0x67:
                self.logger.error("Seed request failed")
                return False
            
            # Extract seed from response (format depends on implementation)
            seed = seed_response.data[1:]  # Assume seed is in data field
            self.logger.info(f"Received seed: {seed.hex()}")
            
            # 2. Calculate key using provided function
            key = seed_key_func(seed)
            self.logger.info(f"Calculated key: {key.hex()}")
            
            # 3. Send key (sub-function = level+1, even number)
            key_response = self.uds.uds_conn.send(
                SecurityAccess(level + 1, key=key)
            )
            
            if key_response and key_response.service_id == 0x67:
                self.logger.info("✓ Security access successful")
                return True
            else:
                self.logger.error("Security access failed: Invalid key")
                return False
                
        except UdsError as e:
            self.logger.error(f"Security access error: {e}")
            return False
    
    # ------------------------------------------------------------------------
    # Read Data By Identifier (0x22)
    # ------------------------------------------------------------------------
    
    def read_did(self, did: int) -> Optional[bytes]:
        """
        Read data by identifier
        
        Args:
            did: Data identifier (e.g., 0xF190 for VIN, 0xF18C for software version)
        """
        try:
            self.logger.info(f"Reading DID 0x{did:04X}...")
            
            response = self.uds.uds_conn.send(
                ReadDataByIdentifier(identifiers=[did])
            )
            
            if response and response.service_id == 0x62:
                # Parse response (format: [DID_high, DID_low, data...])
                data = response.data[2:]  # Skip DID bytes
                self.logger.info(f"✓ DID 0x{did:04X} = {data.hex()}")
                
                # Try to decode as ASCII if it looks like text
                try:
                    ascii_str = data.decode('ascii')
                    if all(32 <= ord(c) <= 126 for c in ascii_str):
                        self.logger.info(f"  ASCII: {ascii_str}")
                except:
                    pass
                    
                return data
            else:
                self.logger.error(f"Read DID failed: {response}")
                return None
                
        except UdsError as e:
            self.logger.error(f"Read DID error: {e}")
            return None
    
    # ------------------------------------------------------------------------
    # Write Data By Identifier (0x2E)
    # ------------------------------------------------------------------------
    
    def write_did(self, did: int, data: bytes) -> bool:
        """
        Write data by identifier
        
        Args:
            did: Data identifier
            data: Data to write
        """
        try:
            self.logger.info(f"Writing to DID 0x{did:04X}: {data.hex()}")
            
            response = self.uds.uds_conn.send(
                WriteDataByIdentifier(identifier=did, data=data)
            )
            
            if response and response.service_id == 0x6E:
                self.logger.info(f"✓ Write successful to DID 0x{did:04X}")
                return True
            else:
                self.logger.error(f"Write failed: {response}")
                return False
                
        except UdsError as e:
            self.logger.error(f"Write error: {e}")
            return False
    
    # ------------------------------------------------------------------------
    # Routine Control (0x31)
    # ------------------------------------------------------------------------
    
    def start_routine(self, routine_id: int, data: bytes = b'') -> Optional[bytes]:
        """
        Start a routine
        
        Args:
            routine_id: Routine identifier
            data: Optional routine data
        """
        try:
            self.logger.info(f"Starting routine 0x{routine_id:04X}...")
            
            response = self.uds.uds_conn.send(
                RoutineControl(
                    routine_type=0x01,  # Start routine
                    routine_id=routine_id,
                    data=data
                )
            )
            
            if response and response.service_id == 0x71:
                result = response.data[2:]  # Skip routine ID bytes
                self.logger.info(f"✓ Routine started successfully")
                if result:
                    self.logger.info(f"  Result: {result.hex()}")
                return result
            else:
                self.logger.error(f"Routine start failed: {response}")
                return None
                
        except UdsError as e:
            self.logger.error(f"Routine error: {e}")
            return None
    
    # ------------------------------------------------------------------------
    # ECU Reset (0x11)
    # ------------------------------------------------------------------------
    
    def ecu_reset(self, reset_type: int = 0x01) -> bool:
        """
        Reset ECU
        
        Args:
            reset_type: Reset type
                0x01 - Hard reset
                0x02 - Key off/on reset
                0x03 - Soft reset
        """
        reset_names = {
            0x01: "Hard Reset",
            0x02: "Key Off/On Reset",
            0x03: "Soft Reset"
        }
        
        reset_name = reset_names.get(reset_type, f"Unknown(0x{reset_type:02X})")
        
        try:
            self.logger.info(f"Performing {reset_name}...")
            
            response = self.uds.uds_conn.send(
                ECUReset(reset_type=reset_type)
            )
            
            if response and response.service_id == 0x51:
                self.logger.info(f"✓ ECU reset successful")
                return True
            else:
                self.logger.error(f"ECU reset failed: {response}")
                return False
                
        except UdsError as e:
            self.logger.error(f"Reset error: {e}")
            return False
    
    # ------------------------------------------------------------------------
    # Tester Present (0x3E)
    # ------------------------------------------------------------------------
    
    def send_tester_present(self) -> bool:
        """
        Send Tester Present message to keep session alive
        """
        try:
            response = self.uds.uds_conn.send(
                TesterPresent()
            )
            return response and response.service_id == 0x7E
        except:
            return False


# ============================================================================
# Example Usage
# ============================================================================

def simple_seed_key_algorithm(seed: bytes) -> bytes:
    """
    Simple seed-key algorithm example
    In real applications, this would be the proprietary algorithm
    """
    # Example: XOR with 0x55 and byte swap
    result = bytearray()
    for b in seed:
        result.append(b ^ 0x55)
    
    # Swap bytes (common in some ECUs)
    if len(result) >= 2:
        result[0], result[1] = result[1], result[0]
    
    return bytes(result)


def main():
    """Main demonstration function"""
    
    print("=" * 70)
    print("UDS + Vector CANoe Integration Example")
    print("=" * 70)
    
    # Create configuration
    config = VectorCanoeConfig()
    
    # Use context manager for automatic cleanup
    with UdsVectorManager(config) as uds_manager:
        
        # Create diagnostic operations wrapper
        diag = UdsDiagnosticOperations(uds_manager)
        
        # --------------------------------------------------------------------
        # Example 1: Switch to Extended Session
        # --------------------------------------------------------------------
        print("\n" + "-" * 50)
        print("1. Diagnostic Session Control")
        print("-" * 50)
        
        if not diag.change_session(0x03):  # Extended session
            print("Failed to switch session. Exiting.")
            return
        
        time.sleep(0.1)
        
        # --------------------------------------------------------------------
        # Example 2: Security Access (if needed)
        # --------------------------------------------------------------------
        print("\n" + "-" * 50)
        print("2. Security Access")
        print("-" * 50)
        
        # Try security level 1
        if not diag.security_access(0x01, simple_seed_key_algorithm):
            print("Security access failed. Continuing with limited functionality...")
        
        time.sleep(0.1)
        
        # --------------------------------------------------------------------
        # Example 3: Read Data Identifiers
        # --------------------------------------------------------------------
        print("\n" + "-" * 50)
        print("3. Read Data By Identifier (0x22)")
        print("-" * 50)
        
        # Read VIN (Vehicle Identification Number) - common DID
        vin_data = diag.read_did(0xF190)
        
        # Read software version
        diag.read_did(0xF18C)
        
        # Read hardware version
        diag.read_did(0xF187)
        
        time.sleep(0.1)
        
        # --------------------------------------------------------------------
        # Example 4: Start a Routine
        # --------------------------------------------------------------------
        print("\n" + "-" * 50)
        print("4. Routine Control (0x31)")
        print("-" * 50)
        
        # Example: Start diagnostic routine (routine ID 0x0202)
        diag.start_routine(0x0202, b'\x01')
        
        time.sleep(0.1)
        
        # --------------------------------------------------------------------
        # Example 5: Send Tester Present
        # --------------------------------------------------------------------
        print("\n" + "-" * 50)
        print("5. Tester Present (keep session alive)")
        print("-" * 50)
        
        if diag.send_tester_present():
            print("Tester Present sent successfully")
        
        time.sleep(0.1)
        
        # --------------------------------------------------------------------
        # Example 6: ECU Reset
        # --------------------------------------------------------------------
        print("\n" + "-" * 50)
        print("6. ECU Reset")
        print("-" * 50)
        
        # Note: This will reset the ECU, ending the session
        # Comment out if you don't want to actually reset
        # diag.ecu_reset(0x01)
        
        print("Demo completed successfully!")


# ============================================================================
# Advanced Example: Multi-Frame Responses
# ============================================================================

def read_large_data_example(uds_manager: UdsVectorManager):
    """
    Example of reading large data that requires multi-frame transfer
    """
    print("\n" + "-" * 50)
    print("Advanced: Reading Large Data (Multi-Frame)")
    print("-" * 50)
    
    # Some ECUs support reading large blocks of memory
    # This would be done via ReadMemoryByAddress (0x23)
    
    try:
        # Example: Read 1000 bytes from address 0x8000
        response = uds_manager.uds_conn.send(
            ReadMemoryByAddress(
                address=0x8000,
                memory_size=1000,
                memory_type=0x00  # Physical memory
            )
        )
        
        if response and response.service_id == 0x63:
            data = response.data
            print(f"Read {len(data)} bytes successfully")
            return data
        else:
            print("Read failed or not supported")
            return None
            
    except UdsError as e:
        print(f"Error reading large data: {e}")
        return None


# ============================================================================
# Error Handling Example
# ============================================================================

def error_handling_example(diag: UdsDiagnosticOperations):
    """
    Example of proper error handling with NACK codes
    """
    print("\n" + "-" * 50)
    print("Error Handling Example")
    print("-" * 50)
    
    try:
        # Try to read an invalid DID
        response = diag.uds.uds_conn.send(
            ReadDataByIdentifier(identifiers=[0xFFFF])
        )
        
        if response is None:
            print("No response (timeout)")
        elif response.service_id == 0x7F:  # Negative response
            # Parse NACK code
            nack_code = response.data[1]
            nack_desc = {
                0x11: "Service Not Supported",
                0x12: "Sub-Function Not Supported",
                0x13: "Incorrect Message Length",
                0x22: "Conditions Not Correct",
                0x31: "Request Out of Range",
                0x33: "Security Access Denied",
                0x35: "Invalid Key",
                0x36: "Exceeded Number of Attempts",
                0x37: "Required Time Delay Not Expired",
            }.get(nack_code, f"Unknown (0x{nack_code:02X})")
            
            print(f"Negative response: {nack_desc}")
            
    except UdsError as e:
        print(f"UDS Error: {e}")


# ============================================================================
# Performance Testing Example
# ============================================================================

def performance_test(diag: UdsDiagnosticOperations, num_requests: int = 10):
    """
    Measure UDS request-response performance
    """
    print("\n" + "-" * 50)
    print(f"Performance Test: {num_requests} requests")
    print("-" * 50)
    
    times = []
    
    for i in range(num_requests):
        start = time.time()
        
        # Read a simple DID
        diag.read_did(0xF190)
        
        elapsed = (time.time() - start) * 1000  # ms
        times.append(elapsed)
        
        print(f"Request {i+1}: {elapsed:.2f} ms")
        
        time.sleep(0.1)  # Small delay between requests
    
    # Statistics
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    
    print(f"\nStatistics:")
    print(f"  Average: {avg_time:.2f} ms")
    print(f"  Min: {min_time:.2f} ms")
    print(f"  Max: {max_time:.2f} ms")


if __name__ == "__main__":
    # Run main example
    main()
    
    # Uncomment for additional examples
    # with UdsVectorManager(VectorCanoeConfig()) as manager:
    #     diag = UdsDiagnosticOperations(manager)
    #     
    #     # Error handling demo
    #     error_handling_example(diag)
    #     
    #     # Performance test
    #     performance_test(diag, 5)