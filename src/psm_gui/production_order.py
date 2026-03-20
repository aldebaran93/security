from dataclasses import dataclass, asdict
import datetime
from typing import List, Dict, Any

# ============================================================================
# Production OrderData Models
# ============================================================================

@dataclass
class ProductionOrder:
    """Production order for a vehicle"""
    vin: str
    model: str
    production_date: datetime.datetime
    ecus: List[Dict[str, Any]]
    status: str = "pending"