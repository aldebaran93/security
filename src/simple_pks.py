# simple_pks.py
"""
Simple Production Key Server for Windows
Runs as a local service for key generation and management
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import uuid
import datetime
import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import uvicorn

app = FastAPI(title="Production Key Server")

# In-memory storage (replace with database in production)
keys_db = {}
vehicles_db = {}

class KeyRequest(BaseModel):
    vin: str
    ecu_type: str
    ecu_serial: str
    key_type: str = "RSA"
    key_size: int = 2048

class KeyResponse(BaseModel):
    key_id: str
    public_key: str
    vin: str
    ecu_serial: str
    created_at: str

class CertificateRequest(BaseModel):
    vin: str
    ecu_serial: str
    common_name: Optional[str] = None

class InjectionReport(BaseModel):
    vin: str
    ecu_serial: str
    key_id: str
    status: str
    operator: str

@app.get("/")
async def root():
    return {"message": "Production Key Server is running"}

@app.post("/api/keys/generate", response_model=KeyResponse)
async def generate_key(request: KeyRequest):
    """Generate RSA key pair for ECU"""
    try:
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=request.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Generate key ID
        key_id = f"key_{uuid.uuid4().hex[:8]}"
        
        # Store key info
        keys_db[key_id] = {
            "private_key": private_key,  # In production, store in HSM
            "public_pem": public_pem.decode('utf-8'),
            "vin": request.vin,
            "ecu_serial": request.ecu_serial,
            "created_at": datetime.datetime.now().isoformat()
        }
        
        # Store in vehicle record
        if request.vin not in vehicles_db:
            vehicles_db[request.vin] = {"ecus": []}
        
        vehicles_db[request.vin]["ecus"].append({
            "ecu_serial": request.ecu_serial,
            "key_id": key_id,
            "type": request.ecu_type
        })
        
        return KeyResponse(
            key_id=key_id,
            public_key=public_pem.decode('utf-8'),
            vin=request.vin,
            ecu_serial=request.ecu_serial,
            created_at=datetime.datetime.now().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/keys/{key_id}")
async def get_key(key_id: str):
    """Retrieve public key by ID"""
    if key_id not in keys_db:
        raise HTTPException(status_code=404, detail="Key not found")
    
    key_info = keys_db[key_id]
    return {
        "key_id": key_id,
        "public_key": key_info["public_pem"],
        "vin": key_info["vin"],
        "ecu_serial": key_info["ecu_serial"],
        "created_at": key_info["created_at"]
    }

@app.post("/api/certificates/create")
async def create_certificate(request: CertificateRequest):
    """Create certificate placeholder (simplified)"""
    cert_id = f"cert_{uuid.uuid4().hex[:8]}"
    
    return {
        "certificate_id": cert_id,
        "vin": request.vin,
        "ecu_serial": request.ecu_serial,
        "common_name": request.common_name or f"ecu-{request.ecu_serial}",
        "status": "pending",
        "created_at": datetime.datetime.now().isoformat()
    }

@app.post("/api/audit/injection")
async def report_injection(report: InjectionReport):
    """Log key injection event"""
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "vin": report.vin,
        "ecu_serial": report.ecu_serial,
        "key_id": report.key_id,
        "status": report.status,
        "operator": report.operator
    }
    
    # Save to audit log file
    with open("audit.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    return {"status": "logged", "entry": log_entry}

@app.get("/api/vehicle/{vin}")
async def get_vehicle_keys(vin: str):
    """Get all keys for a vehicle"""
    if vin not in vehicles_db:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    
    return vehicles_db[vin]

if __name__ == "__main__":
    print("Starting Production Key Server on http://localhost:8000")
    print("Press Ctrl+C to stop")
    uvicorn.run(app, host="0.0.0.0", port=8000)