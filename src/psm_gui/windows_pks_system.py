import tkinter as tk
import logging
import json
import os
import base64
import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path
import requests

class WindowsPKSClient:
    """
    Production Key Server client for Windows
    Works with Infisical (Docker) or native FastAPI server
    """
    
    def __init__(self, server_url: str = "http://localhost:80", 
                 use_infisical: bool = True):
        """
        Initialize client
        
        Args:
            server_url: URL of PKS (Infisical or native server)
            use_infisical: True for Infisical, False for native server
        """
        self.server_url = server_url
        self.use_infisical = use_infisical
        self.token = None
        
        # Windows-specific paths for storing config - CREATE THIS FIRST!
        self.config_dir = Path(os.environ.get('APPDATA', '.')) / 'PKSClient'
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise RuntimeError(f"Failed to create config directory {self.config_dir}: {e}") from e
        self.config_file = self.config_dir / 'config.json'

        # Ensure config file exists with a sane default
        if not self.config_file.exists():
            try:
                self.config_file.write_text(json.dumps({}), encoding='utf-8')
            except Exception as e:
                raise RuntimeError(f"Failed to create config file {self.config_file}: {e}") from e
        
        # NOW setup logger (after config_dir exists)
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        """Configure Windows-compatible logging"""
        logger = logging.getLogger('WindowsPKS')
        logger.setLevel(logging.INFO)
        
        # File handler (Windows paths work with forward/backslashes)
        log_file = self.config_dir / 'pks_client.log'
        handler = logging.FileHandler(str(log_file))
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def connect_infisical(self, client_id: str, client_secret: str) -> bool:
        """
        Connect to Infisical using Universal Auth
        """
        try:
            # Infisical auth endpoint
            auth_url = f"{self.server_url}/api/v1/auth/universal-auth/login"
            
            response = requests.post(
                auth_url,
                json={
                    "clientId": client_id,
                    "clientSecret": client_secret
                }
            )
            
            if response.status_code == 200:
                self.token = response.json()['accessToken']
                self.logger.info("Connected to Infisical")
                return True
            else:
                self.logger.error(f"Auth failed: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            return False
    
    def generate_ecu_key(self, vin: str, ecu_type: str, 
                        ecu_serial: str) -> Optional[Dict[str, Any]]:
        """
        Generate ECU key pair
        
        Args:
            vin: Vehicle Identification Number
            ecu_type: Type of ECU
            ecu_serial: ECU serial number
        
        Returns:
            Dictionary with key_id and public_key
        """
        try:
            if self.use_infisical:
                # Infisical API code remains the same
                if not self.token:
                    self.logger.error("Not authenticated")
                    return None
                
                # Create secret in Infisical
                headers = {"Authorization": f"Bearer {self.token}"}
                
                secret_name = f"ECU_KEY_{vin}_{ecu_serial}"
                secret_value = json.dumps({
                    "vin": vin,
                    "ecu_type": ecu_type,
                    "ecu_serial": ecu_serial,
                    "created": datetime.datetime.now().isoformat()
                })
            
                # Store in Infisical (simplified)
                response = requests.post(
                    f"{self.server_url}/api/v3/secrets/raw/{secret_name}",
                    headers=headers,
                    json={
                        "workspaceId": "your-project-id",
                        "environment": "prod",
                        "secretValue": secret_value,
                        "secretPath": f"/vehicles/{vin}"
                    }
                )
            
                if response.status_code == 200:
                    return {
                        "key_id": secret_name,
                        "public_key": "stored_in_infisical",
                        "vin": vin,
                        "ecu_serial": ecu_serial
                    }
            else:
                # NATIVE SERVER - FIXED ENDPOINT
                # Changed from '/api/keys/request' to '/api/keys/generate'
                response = requests.post(
                    f"{self.server_url}/api/keys/generate",  # CORRECT ENDPOINT
                    json={
                        "vin": vin,
                        "ecu_type": ecu_type,
                        "ecu_serial": ecu_serial,
                        "key_type": "RSA",
                        "key_size": 2048
                    }
                )
            
                if response.status_code == 200:
                    return response.json()
                else:
                    self.logger.error(f"Server returned {response.status_code}: {response.text}")
                    return None
        except Exception as e:
            self.logger.error(f"Key generation failed: {e}")
            return None
        
    def report_injection(self, vin: str, ecu_serial: str, 
                        key_id: str, status: str, operator: str) -> bool:
        """
        Report key injection status for audit trail
        """
        try:
            if not self.use_infisical:
                # Native server
                response = requests.post(
                    f"{self.server_url}/api/audit/injection",
                    json={
                        "vin": vin,
                        "ecu_serial": ecu_serial,
                        "key_id": key_id,
                        "status": status,
                        "operator": operator
                    }
                )
                return response.status_code == 200
            else:
                # Infisical - log as secret or use audit endpoint
                self.logger.info(f"Injection reported: {vin} - {status}")
                return True
                
        except Exception as e:
            self.logger.error(f"Reporting failed: {e}")
            return False
    
    def get_vehicle_keys(self, vin: str) -> Optional[Dict[str, Any]]:
        """Get all keys for a vehicle"""
        try:
            if not self.use_infisical:
                response = requests.get(f"{self.server_url}/api/vehicle/{vin}")
                if response.status_code == 200:
                    return response.json()
            return None
        except Exception as e:
            self.logger.error(f"Failed to get vehicle keys: {e}")
            return None
    
    def request_ecu_keys(self, vin: str, ecu_type: str, 
                        ecu_serial: str) -> Dict[str, Any]:
        """
        Request ECU keys from Production Key Server
        
        Args:
            vin: Vehicle Identification Number
            ecu_type: Type of ECU (e.g., 'EngineControl')
            ecu_serial: ECU serial number
            
        Returns:
            Dictionary containing:
            - encryption_key: Base64 encoded encryption key
            - authentication_key: Base64 encoded authentication key
            - certificate: Base64 encoded certificate
            - key_id: Unique key identifier
            - expiry: Key expiration date
        """
        try:
            if self.use_infisical:
                # Use Infisical to store/retrieve keys
                key_data = self.generate_ecu_key(vin, ecu_type, ecu_serial)
                if key_data:
                    return {
                        'encryption_key': base64.b64encode(os.urandom(32)).decode(),
                        'authentication_key': base64.b64encode(os.urandom(32)).decode(),
                        'certificate': key_data.get('public_key', ''),
                        'key_id': key_data.get('key_id', f"KEY-{vin}"),
                        'expiry': (datetime.datetime.now() + datetime.timedelta(days=365)).isoformat()
                    }
            else:
                # Native API server
                response = requests.post(
                    f"{self.server_url}/api/keys/request",
                    json={
                        "vin": vin,
                        "ecu_type": ecu_type,
                        "ecu_serial": ecu_serial
                    }
                )
                
                if response.status_code == 200:
                    keys = response.json()
                    self.logger.info(f"Keys received for {ecu_type} - VIN: {vin}")
                    return keys
                else:
                    raise Exception(f"Key request failed: {response.text}")
                    
        except Exception as e:
            self.logger.error(f"Key request failed: {e}")
            raise