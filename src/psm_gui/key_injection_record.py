import datetime
from dataclasses import dataclass, asdict
from typing import Optional

# ============================================================================
# Key Injection Record Data Model
# ============================================================================

@dataclass
class KeyInjectionRecord:
    """Record of key injection event"""
    vin: str
    ecu_id: str
    key_type: str
    key_id: str
    injection_time: datetime.datetime
    operator: str
    status: str
    signature: Optional[str] = None