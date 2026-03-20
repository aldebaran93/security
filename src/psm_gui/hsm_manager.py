
import logging
import inspect
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict

# Third-party imports (install with: pip install zeep python-pkcs11 lxml cryptography)
import pkcs11
from pkcs11 import KeyType, ObjectClass, Mechanism, Attribute
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# ============================================================================
# HSM Manager (PKCS#11 Integration)
# ============================================================================

class HSMManager:
    """
    Hardware Security Module (HSM) manager using PKCS#11
    Supports key generation, signing, and secure storage
    """
    
    def __init__(self, pkcs11_lib_path: str, slot: int = 0, pin: str = None):
        """
        Initialize HSM connection
        
        Args:
            pkcs11_lib_path: Path to PKCS#11 library (.dll, .so, .dylib)
            slot: HSM slot number
            pin: User PIN for HSM access
        """
        self.pkcs11_lib_path = pkcs11_lib_path
        self.slot = slot
        self.pin = pin
        self.lib = None
        self.session = None
        self.logger = logging.getLogger(__name__)
        
    def connect(self) -> bool:
        """Establish connection to HSM"""
        try:
            self.logger.info("HSM connect start: lib=%s slot=%s", self.pkcs11_lib_path, self.slot)
            self.lib = pkcs11.lib(self.pkcs11_lib_path)

            # Try explicit slot expectation first when provided
            token = None
            if self.slot is not None:
                try:
                    selected_slot = None
                    for slot_obj in self.lib.get_slots():
                        if getattr(slot_obj, 'id', None) == self.slot or getattr(slot_obj, 'slot_id', None) == self.slot:
                            selected_slot = slot_obj
                            break

                    if selected_slot is not None:
                        token = selected_slot.get_token()
                        self.logger.info("Using configured slot %s token label=%s", self.slot, token.label)
                    else:
                        self.logger.warning("Slot %s not found among available slots", self.slot)
                except Exception as slot_err:
                    self.logger.warning("Slot %s lookup failed: %s", self.slot, slot_err)

            # Fallback: enumerate available slots and pick first initialized token
            if token is None:
                for slot_obj in self.lib.get_slots(token_present=True):
                    try:
                        candidate = slot_obj.get_token()
                        if candidate is None:
                            continue
                        token = candidate
                        self.logger.info("Auto-selected slot %s token label=%s", slot_obj.id, token.label)
                        break
                    except Exception as slot_err:
                        self.logger.warning("Slot iteration token load failed: %s", slot_err)
                        continue

            if token is None:
                raise RuntimeError("No usable HSM token found")

            open_args = {}
            if self.pin is not None:
                open_args['user_pin'] = self.pin

            sig = inspect.signature(token.open)
            if 'rw' in sig.parameters:
                open_args['rw'] = True
            elif 'read_write' in sig.parameters:
                open_args['read_write'] = True
            elif 'rw_session' in sig.parameters:
                open_args['rw_session'] = True

            try:
                self.session = token.open(**open_args)
            except pkcs11.exceptions.TokenNotRecognised as e:
                self.logger.error("HSM token not recognised (slot/token mismatch or invalid token state)", exc_info=True)
                raise
            except pkcs11.exceptions.PinIncorrect as e:
                self.logger.error("HSM PIN incorrect", exc_info=True)
                raise

            self.logger.info(f"Connected to HSM: {token.label}")
            return True

        except Exception as e:
            self.logger.error("HSM connection failed", exc_info=True)
            return False
    
    def disconnect(self):
        """Close HSM session"""
        if self.session:
            self.session.close()
            self.logger.info("HSM session closed")
    
    def generate_key_pair(self, key_label: str, key_type: str = "RSA", 
                          key_size: int = 2048) -> Dict[str, Any]:
        """
        Generate key pair in HSM
        
        Returns:
            Dictionary with key handles and metadata
        """
        try:
            if key_type.upper() == "RSA":
                # Generate RSA key pair
                public_key, private_key = self.session.generate_keypair(
                    KeyType.RSA,
                    key_size,
                    id=key_label.encode(),
                    label=key_label,
                    store=True,
                    public_template={
                        Attribute.VERIFY: True,
                        Attribute.ENCRYPT: True,
                        Attribute.WRAP: True,
                    },
                    private_template={
                        Attribute.SIGN: True,
                        Attribute.DECRYPT: True,
                        Attribute.UNWRAP: True,
                    }
                )
                
                # Export public key for external use
                pub_key_der = public_key[Attribute.VALUE]
                pub_key_pem = serialization.load_der_public_key(
                    pub_key_der, backend=default_backend()
                ).public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                return {
                    'private_handle': private_key.key,
                    'public_handle': public_key.key,
                    'public_key_pem': pub_key_pem.decode(),
                    'key_label': key_label,
                    'key_type': key_type,
                    'key_size': key_size
                }
            else:
                raise ValueError(f"Unsupported key type: {key_type}")
                
        except Exception as e:
            self.logger.error(f"Key generation failed: {e}")
            raise
    
    def sign_data(self, key_label: str, data: bytes, 
                  mechanism: Mechanism = Mechanism.SHA256_RSA_PKCS) -> bytes:
        """
        Sign data using private key from HSM
        """
        try:
            # Find private key by label
            private_key = self.session.get_key(
                object_class=ObjectClass.PRIVATE_KEY,
                key_type=KeyType.RSA,
                label=key_label
            )

        except pkcs11.exceptions.NoSuchKey:
            self.logger.warning("Private key '%s' not found, generating new RSA key pair", key_label)
            self.generate_key_pair(key_label, key_type="RSA", key_size=2048)
            private_key = self.session.get_key(
                object_class=ObjectClass.PRIVATE_KEY,
                key_type=KeyType.RSA,
                label=key_label
            )

        except Exception as e:
            self.logger.error(f"Signing failed: {e}")
            raise

        try:
            signature = private_key.sign(data, mechanism=mechanism)
            return signature

        except Exception as e:
            self.logger.error(f"Signing failed: {e}")
            raise
    
    def get_public_key(self, key_label: str) -> bytes:
        """
        Retrieve public key from HSM
        """
        try:
            public_key = self.session.get_key(
                object_class=ObjectClass.PUBLIC_KEY,
                key_type=KeyType.RSA,
                label=key_label
            )

        except pkcs11.exceptions.NoSuchKey:
            self.logger.warning("Public key '%s' not found, generating key pair", key_label)
            self.generate_key_pair(key_label, key_type="RSA", key_size=2048)
            public_key = self.session.get_key(
                object_class=ObjectClass.PUBLIC_KEY,
                key_type=KeyType.RSA,
                label=key_label
            )

        except Exception as e:
            self.logger.error(f"Failed to get public key: {e}")
            raise

        try:
            return public_key[Attribute.VALUE]

        except Exception as e:
            self.logger.error(f"Failed to extract public key value: {e}")
            raise
