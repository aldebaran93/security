from dataclasses import dataclass, asdict

# ============================================================================
# ECU Data Models
# ============================================================================

@dataclass
class ECUConfig:
    """ECU configuration for production"""
    ecu_type: str
    part_number: str
    hardware_version: str
    software_version: str
    security_level: int
    requires_secure_boot: bool
    requires_key_injection: bool