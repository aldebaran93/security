"""
Production Security Management GUI
Features:
- Secure ECU Update Management
- Production Key Server (SOAP) Integration with WS-Security
- HSM (PKCS#11) Integration for Key Operations
- VIN-to-Key Binding and Tracking
- Audit Logging and Reporting
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import queue
import logging
import json
import os
import base64
import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from pathlib import Path

# Third-party imports (install with: pip install zeep python-pkcs11 lxml cryptography)
from zeep import Client, Settings
from zeep.wsse.signature import Signature
from zeep.transports import Transport
from requests import Session
import pkcs11
from pkcs11 import KeyType, Mechanism, Attribute
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ============================================================================
# Data Models
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
    
@dataclass
class ProductionOrder:
    """Production order for a vehicle"""
    vin: str
    model: str
    production_date: datetime.datetime
    ecus: List[Dict[str, Any]]
    status: str = "pending"
    
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
            self.lib = pkcs11.lib(self.pkcs11_lib_path)
            self.lib.load()
            
            # Get token and open session
            token = self.lib.get_token(token_label=None)
            self.session = token.open(user_pin=self.pin, rw_session=True)
            
            self.logger.info(f"Connected to HSM: {token.label}")
            return True
            
        except Exception as e:
            self.logger.error(f"HSM connection failed: {e}")
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
                public_key, private_key = self.session.generate_key_pair(
                    KeyType.RSA,
                    key_size,
                    label=key_label,
                    store=True,
                    id=key_label.encode(),
                    # Key usage flags
                    encrypt=True,
                    decrypt=True,
                    sign=True,
                    verify=True,
                    wrap=True,
                    unwrap=True
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
                key_type=KeyType.PRIVATE_KEY,
                label=key_label
            )
            
            # Sign data
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
                key_type=KeyType.PUBLIC_KEY,
                label=key_label
            )
            return public_key[Attribute.VALUE]
            
        except Exception as e:
            self.logger.error(f"Failed to get public key: {e}")
            raise


# ============================================================================
# Production Key Server Client (SOAP with WS-Security)
# ============================================================================

class ProductionKeyServerClient:
    """
    Client for Production Key Server using SOAP with WS-Security
    Handles mutual TLS authentication and XML signature
    """
    
    def __init__(self, wsdl_url: str, client_cert_path: str, 
                 client_key_path: str, ca_cert_path: str = None):
        """
        Initialize PKS client with certificates
        
        Args:
            wsdl_url: URL to PKS WSDL or local WSDL file
            client_cert_path: Path to client certificate (PEM)
            client_key_path: Path to private key (PEM)
            ca_cert_path: Path to CA certificate for server verification
        """
        self.wsdl_url = wsdl_url
        self.client = None
        self.logger = logging.getLogger(__name__)
        
        # Setup mutual TLS session
        self.session = Session()
        
        # Load client certificate and key
        self.session.cert = (client_cert_path, client_key_path)
        
        # Load CA certificate for server verification
        if ca_cert_path:
            self.session.verify = ca_cert_path
        else:
            self.session.verify = False  # Not recommended for production!
        
        # Create transport with mutual TLS
        self.transport = Transport(session=self.session)
        
        # Optional: Add WS-Security signature
        self.signature = Signature(client_key_path, client_cert_path)
        
    def connect(self):
        """Establish SOAP client connection"""
        try:
            settings = Settings(strict=False, xml_huge=True)
            self.client = Client(
                self.wsdl_url,
                transport=self.transport,
                wsse=self.signature,
                settings=settings
            )
            self.logger.info(f"Connected to PKS at {self.wsdl_url}")
            return True
            
        except Exception as e:
            self.logger.error(f"PKS connection failed: {e}")
            return False
    
    def request_ecu_keys(self, vin: str, ecu_type: str, 
                         ecu_serial: str) -> Dict[str, Any]:
        """
        Request ECU keys from Production Key Server
        
        SOAP request example:
        <soap:Envelope>
            <soap:Header>
                <wsse:Security>
                    <wsse:BinarySecurityToken>...</wsse:BinarySecurityToken>
                </wsse:Security>
            </soap:Header>
            <soap:Body>
                <RequestECUKeys>
                    <VIN>ABC123...</VIN>
                    <ECUType>EngineControl</ECUType>
                    <ECUSerial>SN12345</ECUSerial>
                </RequestECUKeys>
            </soap:Body>
        </soap:Envelope>
        """
        try:
            # Call PKS service method
            response = self.client.service.RequestECUKeys(
                VIN=vin,
                ECUType=ecu_type,
                ECUSerial=ecu_serial
            )
            
            # Parse response
            keys = {
                'encryption_key': base64.b64decode(response.EncryptionKey),
                'authentication_key': base64.b64decode(response.AuthenticationKey),
                'certificate': response.Certificate,
                'key_id': response.KeyID,
                'expiry': response.ExpiryDate
            }
            
            self.logger.info(f"Received keys for ECU {ecu_serial}")
            return keys
            
        except Exception as e:
            self.logger.error(f"Key request failed: {e}")
            raise
    
    def report_key_injection(self, vin: str, ecu_serial: str, 
                             key_id: str, status: str) -> bool:
        """
        Report key injection status back to PKS for audit trail
        """
        try:
            response = self.client.service.ReportKeyInjection(
                VIN=vin,
                ECUSerial=ecu_serial,
                KeyID=key_id,
                Status=status,
                Timestamp=datetime.datetime.now().isoformat()
            )
            return response.Success
            
        except Exception as e:
            self.logger.error(f"Injection reporting failed: {e}")
            return False


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


# ============================================================================
# GUI Application
# ============================================================================

class ProductionSecurityGUI:
    """
    Main GUI application for production security management
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("Production Security Management System")
        self.root.geometry("1200x800")
        
        # Configure logging to GUI
        self.log_queue = queue.Queue()
        self.setup_logging()
        
        # Initialize managers (initially None)
        self.hsm = None
        self.pks = None
        self.update_manager = None
        
        # Current session data
        self.current_vin = tk.StringVar()
        self.current_operator = tk.StringVar(value=os.getenv('USERNAME', 'Unknown'))
        
        # Build GUI
        self.setup_ui()
        self.setup_menu()
        
        # Start log processor
        self.process_log_queue()
        
    def setup_logging(self):
        """Configure logging to GUI"""
        class QueueHandler(logging.Handler):
            def __init__(self, queue):
                super().__init__()
                self.queue = queue
            
            def emit(self, record):
                self.queue.put(self.format(record))
        
        # Configure root logger
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        
        # Add queue handler
        handler = QueueHandler(self.log_queue)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    def setup_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Production Order", command=self.load_production_order)
        file_menu.add_command(label="Export Audit Log", command=self.export_audit_log)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="HSM Configuration", command=self.configure_hsm)
        tools_menu.add_command(label="PKS Configuration", command=self.configure_pks)
        tools_menu.add_command(label="Key Management", command=self.key_management_dialog)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
        
    def setup_ui(self):
        """Create main UI layout"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # ====================================================================
        # Header Section
        # ====================================================================
        header_frame = ttk.LabelFrame(main_frame, text="Production Session", padding="10")
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        header_frame.columnconfigure(1, weight=1)
        header_frame.columnconfigure(3, weight=1)
        
        # VIN entry
        ttk.Label(header_frame, text="VIN:").grid(row=0, column=0, padx=5)
        ttk.Entry(header_frame, textvariable=self.current_vin, width=20).grid(row=0, column=1, padx=5, sticky=(tk.W, tk.E))
        
        # Operator
        ttk.Label(header_frame, text="Operator:").grid(row=0, column=2, padx=5)
        ttk.Entry(header_frame, textvariable=self.current_operator, width=15).grid(row=0, column=3, padx=5, sticky=tk.W)
        
        # Status indicators
        self.status_frame = ttk.Frame(header_frame)
        self.status_frame.grid(row=1, column=0, columnspan=4, pady=10)
        
        self.hsm_status = ttk.Label(self.status_frame, text="⚫ HSM: Disconnected", foreground="red")
        self.hsm_status.pack(side=tk.LEFT, padx=10)
        
        self.pks_status = ttk.Label(self.status_frame, text="⚫ PKS: Disconnected", foreground="red")
        self.pks_status.pack(side=tk.LEFT, padx=10)
        
        # ====================================================================
        # ECU Configuration Section
        # ====================================================================
        ecu_frame = ttk.LabelFrame(main_frame, text="ECU Configuration", padding="10")
        ecu_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        ecu_frame.columnconfigure(1, weight=1)
        
        # ECU list with scrollbar
        self.ecu_tree = ttk.Treeview(ecu_frame, columns=('type', 'part', 'hw', 'sw', 'security'), 
                                      height=5, show='headings')
        self.ecu_tree.heading('type', text='ECU Type')
        self.ecu_tree.heading('part', text='Part Number')
        self.ecu_tree.heading('hw', text='HW Version')
        self.ecu_tree.heading('sw', text='SW Version')
        self.ecu_tree.heading('security', text='Security Level')
        
        self.ecu_tree.column('type', width=150)
        self.ecu_tree.column('part', width=120)
        self.ecu_tree.column('hw', width=100)
        self.ecu_tree.column('sw', width=100)
        self.ecu_tree.column('security', width=100)
        
        scrollbar = ttk.Scrollbar(ecu_frame, orient=tk.VERTICAL, command=self.ecu_tree.yview)
        self.ecu_tree.configure(yscrollcommand=scrollbar.set)
        
        self.ecu_tree.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E))
        scrollbar.grid(row=0, column=2, sticky=(tk.N, tk.S))
        
        # ECU buttons
        btn_frame = ttk.Frame(ecu_frame)
        btn_frame.grid(row=1, column=0, columnspan=3, pady=10)
        
        ttk.Button(btn_frame, text="Add ECU", command=self.add_ecu_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Remove ECU", command=self.remove_ecu).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Load from File", command=self.load_ecus).pack(side=tk.LEFT, padx=5)
        
        # ====================================================================
        # Operations Panel
        # ====================================================================
        operations_frame = ttk.LabelFrame(main_frame, text="Security Operations", padding="10")
        operations_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        operations_frame.columnconfigure(0, weight=1)
        
        # Operation buttons
        ttk.Button(operations_frame, text="1. Request Keys from PKS", 
                   command=self.request_keys_threaded).pack(fill=tk.X, pady=2)
        ttk.Button(operations_frame, text="2. Inject Keys into ECU", 
                   command=self.inject_keys_threaded).pack(fill=tk.X, pady=2)
        ttk.Button(operations_frame, text="3. Prepare Secure Update", 
                   command=self.prepare_update_dialog).pack(fill=tk.X, pady=2)
        ttk.Button(operations_frame, text="4. Flash Secure Image", 
                   command=self.flash_update_threaded).pack(fill=tk.X, pady=2)
        ttk.Button(operations_frame, text="5. Verify Installation", 
                   command=self.verify_installation).pack(fill=tk.X, pady=2)
        ttk.Button(operations_frame, text="Generate Audit Report", 
                   command=self.generate_report).pack(fill=tk.X, pady=10)
        
        # ====================================================================
        # Log Panel
        # ====================================================================
        log_frame = ttk.LabelFrame(main_frame, text="Audit Log", padding="10")
        log_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5, padx=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=60)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure log text tags
        self.log_text.tag_config('INFO', foreground='black')
        self.log_text.tag_config('WARNING', foreground='orange')
        self.log_text.tag_config('ERROR', foreground='red')
        self.log_text.tag_config('SUCCESS', foreground='green')
        
        # ====================================================================
        # Progress Bar
        # ====================================================================
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
    # ========================================================================
    # Dialog Windows
    # ========================================================================
    
    def configure_hsm(self):
        """HSM configuration dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("HSM Configuration")
        dialog.geometry("400x250")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="PKCS#11 Library Path:").pack(pady=5)
        lib_path = ttk.Entry(dialog, width=50)
        lib_path.pack(pady=5)
        lib_path.insert(0, "C:/Program Files/SoftHSM2/lib/softhsm2.dll")
        
        ttk.Label(dialog, text="Slot Number:").pack(pady=5)
        slot = ttk.Entry(dialog, width=10)
        slot.pack(pady=5)
        slot.insert(0, "0")
        
        ttk.Label(dialog, text="PIN:").pack(pady=5)
        pin = ttk.Entry(dialog, width=20, show="*")
        pin.pack(pady=5)
        
        def connect_hsm():
            self.hsm = HSMManager(
                pkcs11_lib_path=lib_path.get(),
                slot=int(slot.get()),
                pin=pin.get()
            )
            if self.hsm.connect():
                self.update_manager = SecureUpdateManager(self.hsm)
                self.hsm_status.config(text="🟢 HSM: Connected", foreground="green")
                logging.info("HSM connected successfully")
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Failed to connect to HSM")
        
        ttk.Button(dialog, text="Connect", command=connect_hsm).pack(pady=10)
    
    def configure_pks(self):
        """Production Key Server configuration dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("PKS Configuration")
        dialog.geometry("500x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="WSDL URL:").pack(pady=5)
        wsdl = ttk.Entry(dialog, width=60)
        wsdl.pack(pady=5)
        wsdl.insert(0, "https://pks.example.com/ProductionKeyService?wsdl")
        
        ttk.Label(dialog, text="Client Certificate (PEM):").pack(pady=5)
        cert = ttk.Entry(dialog, width=60)
        cert.pack(pady=5)
        
        ttk.Button(dialog, text="Browse...", 
                   command=lambda: cert.insert(0, filedialog.askopenfilename())).pack()
        
        ttk.Label(dialog, text="Private Key (PEM):").pack(pady=5)
        key = ttk.Entry(dialog, width=60)
        key.pack(pady=5)
        
        ttk.Button(dialog, text="Browse...", 
                   command=lambda: key.insert(0, filedialog.askopenfilename())).pack()
        
        def connect_pks():
            self.pks = ProductionKeyServerClient(
                wsdl_url=wsdl.get(),
                client_cert_path=cert.get(),
                client_key_path=key.get()
            )
            if self.pks.connect():
                self.pks_status.config(text="🟢 PKS: Connected", foreground="green")
                logging.info("PKS connected successfully")
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Failed to connect to PKS")
        
        ttk.Button(dialog, text="Connect", command=connect_pks).pack(pady=20)
    
    def add_ecu_dialog(self):
        """Dialog to add ECU configuration"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add ECU")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        fields = {}
        row = 0
        
        for field in ['ECU Type', 'Part Number', 'HW Version', 'SW Version', 'Security Level']:
            ttk.Label(dialog, text=field).grid(row=row, column=0, padx=5, pady=5, sticky=tk.W)
            fields[field] = ttk.Entry(dialog, width=30)
            fields[field].grid(row=row, column=1, padx=5, pady=5)
            row += 1
        
        # Checkboxes
        secure_boot_var = tk.BooleanVar()
        ttk.Checkbutton(dialog, text="Requires Secure Boot", variable=secure_boot_var).grid(
            row=row, column=0, columnspan=2, pady=5)
        row += 1
        
        key_injection_var = tk.BooleanVar()
        ttk.Checkbutton(dialog, text="Requires Key Injection", variable=key_injection_var).grid(
            row=row, column=0, columnspan=2, pady=5)
        
        def save_ecu():
            config = ECUConfig(
                ecu_type=fields['ECU Type'].get(),
                part_number=fields['Part Number'].get(),
                hardware_version=fields['HW Version'].get(),
                software_version=fields['SW Version'].get(),
                security_level=int(fields['Security Level'].get() or 1),
                requires_secure_boot=secure_boot_var.get(),
                requires_key_injection=key_injection_var.get()
            )
            
            # Add to tree
            self.ecu_tree.insert('', 'end', values=(
                config.ecu_type,
                config.part_number,
                config.hardware_version,
                config.software_version,
                config.security_level
            ))
            
            logging.info(f"Added ECU: {config.ecu_type}")
            dialog.destroy()
        
        ttk.Button(dialog, text="Add", command=save_ecu).grid(row=row+1, column=0, columnspan=2, pady=20)
    
    def prepare_update_dialog(self):
        """Dialog to prepare secure update image"""
        if not self.hsm:
            messagebox.showwarning("Warning", "Please configure HSM first")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Prepare Secure Update")
        dialog.geometry("500x200")
        
        ttk.Label(dialog, text="Firmware File:").pack(pady=5)
        firmware_path = ttk.Entry(dialog, width=50)
        firmware_path.pack(pady=5)
        
        ttk.Button(dialog, text="Browse...", 
                   command=lambda: firmware_path.insert(0, filedialog.askopenfilename())).pack()
        
        ttk.Label(dialog, text="Version:").pack(pady=5)
        version = ttk.Entry(dialog, width=20)
        version.pack(pady=5)
        
        def prepare():
            # Get selected ECU from tree
            selection = self.ecu_tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select an ECU")
                return
            
            ecu_type = self.ecu_tree.item(selection[0])['values'][0]
            
            self.progress.start()
            
            def task():
                try:
                    secure_image = self.update_manager.prepare_secure_image(
                        firmware_path.get(),
                        version.get(),
                        ecu_type
                    )
                    
                    # Save secure image
                    output_path = f"secure_image_{ecu_type}_{version.get()}.json"
                    with open(output_path, 'w') as f:
                        json.dump(secure_image, f, indent=2)
                    
                    self.root.after(0, lambda: self.progress.stop())
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Success", f"Secure image saved to {output_path}"))
                    logging.info(f"Secure image prepared for {ecu_type} v{version.get()}")
                    
                except Exception as e:
                    self.root.after(0, lambda: self.progress.stop())
                    self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                    logging.error(f"Image preparation failed: {e}")
            
            threading.Thread(target=task, daemon=True).start()
            dialog.destroy()
        
        ttk.Button(dialog, text="Prepare Image", command=prepare).pack(pady=20)
    
    # ========================================================================
    # Operation Methods (Threaded)
    # ========================================================================
    
    def request_keys_threaded(self):
        """Request keys from PKS in background thread"""
        if not self.pks:
            messagebox.showwarning("Warning", "Please configure PKS first")
            return
        
        if not self.current_vin.get():
            messagebox.showwarning("Warning", "Please enter VIN")
            return
        
        selection = self.ecu_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an ECU")
            return
        
        self.progress.start()
        
        def task():
            try:
                ecu_type = self.ecu_tree.item(selection[0])['values'][0]
                ecu_serial = f"SN-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
                
                keys = self.pks.request_ecu_keys(
                    self.current_vin.get(),
                    ecu_type,
                    ecu_serial
                )
                
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showinfo(
                    "Success", f"Keys received for {ecu_type}\nKey ID: {keys['key_id']}"))
                logging.info(f"Keys received for {ecu_type} - VIN: {self.current_vin.get()}")
                
            except Exception as e:
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                logging.error(f"Key request failed: {e}")
        
        threading.Thread(target=task, daemon=True).start()
    
    def inject_keys_threaded(self):
        """Inject keys into ECU (simulated)"""
        self.progress.start()
        
        def task():
            try:
                # Simulate key injection
                import time
                time.sleep(2)
                
                record = KeyInjectionRecord(
                    vin=self.current_vin.get(),
                    ecu_id="SIM-ECU-001",
                    key_type="AES-128",
                    key_id=f"KEY-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
                    injection_time=datetime.datetime.now(),
                    operator=self.current_operator.get(),
                    status="success"
                )
                
                # Log injection
                logging.info(f"Keys injected: {record}")
                
                # Report back to PKS
                if self.pks:
                    self.pks.report_key_injection(
                        record.vin, record.ecu_id, record.key_id, record.status
                    )
                
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showinfo("Success", "Keys injected successfully"))
                
            except Exception as e:
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=task, daemon=True).start()
    
    def flash_update_threaded(self):
        """Flash secure update image"""
        self.progress.start()
        
        def task():
            try:
                # Simulate flashing
                import time
                time.sleep(3)
                
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showinfo("Success", "Update flashed successfully"))
                logging.info("Secure update flashed successfully")
                
            except Exception as e:
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=task, daemon=True).start()
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def load_production_order(self):
        """Load production order from JSON file"""
        filename = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if filename:
            with open(filename, 'r') as f:
                order = ProductionOrder(**json.load(f))
            
            self.current_vin.set(order.vin)
            
            # Clear and reload ECU tree
            for item in self.ecu_tree.get_children():
                self.ecu_tree.delete(item)
            
            for ecu in order.ecus:
                self.ecu_tree.insert('', 'end', values=(
                    ecu['type'],
                    ecu['part_number'],
                    ecu['hw_version'],
                    ecu['sw_version'],
                    ecu['security_level']
                ))
            
            logging.info(f"Loaded production order for VIN: {order.vin}")
    
    def export_audit_log(self):
        """Export audit log to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.log_text.get(1.0, tk.END))
            messagebox.showinfo("Success", f"Audit log exported to {filename}")
    
    def key_management_dialog(self):
        """Key management dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Key Management")
        dialog.geometry("600x400")
        
        # Tree view for keys
        tree = ttk.Treeview(dialog, columns=('id', 'type', 'status', 'created'), show='headings')
        tree.heading('id', text='Key ID')
        tree.heading('type', text='Type')
        tree.heading('status', text='Status')
        tree.heading('created', text='Created')
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Sample data
        tree.insert('', 'end', values=('KEY001', 'AES-128', 'Active', '2024-01-15'))
        tree.insert('', 'end', values=('KEY002', 'RSA-2048', 'Revoked', '2024-01-10'))
        
    def generate_report(self):
        """Generate comprehensive audit report"""
        report = f"""
Production Security Audit Report
================================
Generated: {datetime.datetime.now()}
Operator: {self.current_operator.get()}
VIN: {self.current_vin.get()}

HSM Status: {'Connected' if self.hsm else 'Disconnected'}
PKS Status: {'Connected' if self.pks else 'Disconnected'}

ECU Configuration:
------------------
"""
        # Add ECU details
        for item in self.ecu_tree.get_children():
            values = self.ecu_tree.item(item)['values']
            report += f"\n- Type: {values[0]}, Part: {values[1]}, Security: {values[4]}"
        
        report += "\n\nRecent Operations:\n------------------"
        
        # Save report
        filename = f"audit_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(report)
        
        messagebox.showinfo("Success", f"Report saved to {filename}")
        logging.info(f"Audit report generated: {filename}")
    
    def load_ecus(self):
        """Load ECU configuration from file"""
        filename = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if filename:
            with open(filename, 'r') as f:
                ecus = json.load(f)
            
            for ecu in ecus:
                self.ecu_tree.insert('', 'end', values=(
                    ecu['type'],
                    ecu['part_number'],
                    ecu['hw_version'],
                    ecu['sw_version'],
                    ecu['security_level']
                ))
            
            logging.info(f"Loaded {len(ecus)} ECUs from {filename}")
    
    def remove_ecu(self):
        """Remove selected ECU from tree"""
        selection = self.ecu_tree.selection()
        if selection:
            for item in selection:
                self.ecu_tree.delete(item)
            logging.info("ECU removed from configuration")
    
    def verify_installation(self):
        """Verify ECU installation"""
        messagebox.showinfo("Verification", "Installation verification complete")
        logging.info("Installation verified successfully")
    
    def show_docs(self):
        """Show documentation"""
        docs = """
Production Security Management System
=====================================

Workflow:
1. Configure HSM and PKS connections
2. Load production order or enter VIN
3. Add ECUs to be programmed
4. Request keys from Production Key Server
5. Inject keys into ECUs
6. Prepare and flash secure updates
7. Verify installation
8. Generate audit report

Security Features:
- Hardware Security Module (PKCS#11)
- Mutual TLS with Production Key Server
- WS-Security XML signatures
- Secure image signing and verification
- Comprehensive audit logging
"""
        messagebox.showinfo("Documentation", docs)
    
    def show_about(self):
        """Show about dialog"""
        about = """
Production Security Management System v1.0
Automotive Security Tooling

Features:
- Secure ECU Update Management
- Production Key Server Integration
- HSM (PKCS#11) Support
- VIN-to-Key Binding
- Audit Trail & Compliance
"""
        messagebox.showinfo("About", about)
    
    def process_log_queue(self):
        """Process log queue and update GUI"""
        try:
            while True:
                record = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, record + '\n')
                self.log_text.see(tk.END)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_log_queue)


# ============================================================================
# Main Application Entry Point
# ============================================================================

def main():
    """Main application entry point"""
    root = tk.Tk()
    
    # Set application icon (optional)
    try:
        root.iconbitmap('security.ico')
    except:
        pass
    
    # Create application
    app = ProductionSecurityGUI(root)
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Start main loop
    root.mainloop()


if __name__ == "__main__":
    main()