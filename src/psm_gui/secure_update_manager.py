import logging
import json
import base64
import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict

# Third-party imports (install with: pip install zeep python-pkcs11 lxml cryptography)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from security.src.psm_gui.hsm_manager import HSMManager

# ============================================================================
# Secure Update Manager
# ============================================================================

class SecureUpdateManager:
    """
    Manages secure ECU updates with cryptographic verification
    Handles signature verification and secure flashing
    """
    
    def __init__(self, hsm_manager: HSMManager):
        self.hsm = hsm_manager
        self.logger = logging.getLogger(__name__)
        
    def prepare_secure_image(self, firmware_path: str, 
                             version: str, ecu_type: str) -> Dict[str, Any]:
        """
        Prepare firmware image with secure metadata
        """
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()
        
        # Calculate firmware hash
        import hashlib
        firmware_hash = hashlib.sha256(firmware_data).digest()
        
        # Create metadata
        metadata = {
            'ecu_type': ecu_type,
            'version': version,
            'timestamp': datetime.datetime.now().isoformat(),
            'firmware_size': len(firmware_data),
            'hash': base64.b64encode(firmware_hash).decode()
        }
        
        # Sign metadata with HSM
        metadata_bytes = json.dumps(metadata).encode()
        signature = self.hsm.sign_data('update_signing_key', metadata_bytes)
        
        # Package secure image
        secure_image = {
            'metadata': metadata,
            'signature': base64.b64encode(signature).decode(),
            'firmware': base64.b64encode(firmware_data).decode()
        }
        
        return secure_image
    
    def verify_secure_image(self, secure_image: Dict[str, Any]) -> bool:
        """
        Verify signature of secure image before flashing
        """
        try:
            # Recreate metadata bytes
            metadata_bytes = json.dumps(secure_image['metadata']).encode()
            signature = base64.b64decode(secure_image['signature'])
            
            # Get public key from HSM
            public_key_der = self.hsm.get_public_key('update_signing_key')
            public_key = serialization.load_der_public_key(
                public_key_der, backend=default_backend()
            )
            
            # Verify signature
            public_key.verify(
                signature,
                metadata_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # Verify firmware hash
            import hashlib
            firmware_data = base64.b64decode(secure_image['firmware'])
            calculated_hash = hashlib.sha256(firmware_data).digest()
            expected_hash = base64.b64decode(secure_image['metadata']['hash'])
            
            return calculated_hash == expected_hash
            
        except Exception as e:
            self.logger.error(f"Image verification failed: {e}")
            return False
