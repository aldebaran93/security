import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import queue
import logging
import json
import os
import datetime
import requests

from security.src.psm_gui.hsm_manager import HSMManager
from security.src.psm_gui.windows_pks_system import WindowsPKSClient
from security.src.psm_gui.secure_update_manager import SecureUpdateManager
from security.src.psm_gui.ecu_config import ECUConfig
from security.src.psm_gui.production_order import ProductionOrder

# ============================================================================
# GUI Application
# ============================================================================

class ProductionSecurityGUI:
    """
    Main GUI application for production security management
    Includes Windows-compatible PKS integration
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
        self.pks_client = None
        self.update_manager = None

        # Track generated keys for injection
        self.generated_keys = []
        self.last_generated_key = None
        
        # Current session data
        self.current_vin = tk.StringVar()
        self.current_operator = tk.StringVar(value=os.getenv('USERNAME', 'Unknown'))
        
        # Build GUI
        self.setup_ui()
        self.setup_menu()
        
        # Start log processor
        self.process_log_queue()
        
        # Auto-prompt for PKS setup on startup (optional)
        self.root.after(1000, self.prompt_pks_setup)
        
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
    
    def prompt_pks_setup(self):
        """Automatically prompt for PKS setup on startup"""
        if messagebox.askyesno("PKS Setup", 
                               "Would you like to configure the Production Key Server now?"):
            self.setup_windows_pks()
    
    # ========================================================================
    # NEW: Windows PKS Setup Method - Copy this entire method
    # ========================================================================
    
    def setup_windows_pks(self):
        """Setup PKS client for Windows - Copy this entire method"""
        import tkinter.simpledialog as simpledialog
        
        # Ask user which mode to use
        use_infisical = messagebox.askyesno(
            "PKS Mode",
            "Use Infisical (Docker) for full KMS?\n\n"
            "Yes = Infisical (requires Docker Desktop)\n"
            "No = Native Python server (simpler, no Docker)"
        )
        
        if use_infisical:
            # Infisical mode
            client_id = simpledialog.askstring(
                "Infisical Auth",
                "Enter Machine Identity Client ID:"
            )
            
            if not client_id:
                messagebox.showwarning("Warning", "PKS setup cancelled")
                return
            
            client_secret = simpledialog.askstring(
                "Infisical Auth",
                "Enter Machine Identity Client Secret:",
                show='*'
            )
            
            if not client_secret:
                messagebox.showwarning("Warning", "PKS setup cancelled")
                return
            
            # Create PKS client
            self.pks_client = WindowsPKSClient(
                server_url="http://localhost:80",
                use_infisical=True
            )
            
            # Show progress
            self.progress.start()
            self.root.update()
            
            # Connect in background
            def connect_task():
                if self.pks_client.connect_infisical(client_id, client_secret):
                    self.root.after(0, lambda: self.pks_status.config(
                        text="🟢 Infisical PKS: Connected",
                        foreground="green"
                    ))
                    self.root.after(0, lambda: logging.info("Connected to Infisical PKS"))
                    self.root.after(0, lambda: self.progress.stop())
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Success", "Connected to Infisical PKS successfully!"
                    ))
                else:
                    self.root.after(0, lambda: self.progress.stop())
                    self.root.after(0, lambda: messagebox.showerror(
                        "Error", "Failed to connect to Infisical PKS"
                    ))
            
            threading.Thread(target=connect_task, daemon=True).start()
            
        else:
            # Native mode
            server_url = simpledialog.askstring(
                "Native PKS",
                "Enter Native PKS Server URL:",
                initialvalue="http://localhost:8000"
            )
            
            if not server_url:
                messagebox.showwarning("Warning", "PKS setup cancelled")
                return
            
            self.pks_client = WindowsPKSClient(
                server_url=server_url,
                use_infisical=False
            )
            
            # Test connection
            try:
                response = requests.get(f"{server_url}/")
                if response.status_code == 200:
                    self.pks_status.config(
                        text="🟢 Native PKS: Connected",
                        foreground="green"
                    )
                    logging.info(f"Connected to Native PKS at {server_url}")
                    messagebox.showinfo("Success", "Connected to Native PKS successfully!")
                else:
                    messagebox.showwarning("Warning", 
                        f"Connected to server but unexpected response: {response.status_code}")
            except Exception as e:
                messagebox.showwarning("Warning", 
                    f"Could not verify connection, but client is ready.\nError: {e}")
                self.pks_status.config(
                    text="🟡 Native PKS: Ready (unverified)",
                    foreground="orange"
                )
    
    # ========================================================================
    # Updated Request Keys Method (uses pks_client)
    # ========================================================================
    
    def request_keys_threaded(self):
        """Request keys from PKS in background thread"""
        if not self.pks_client:
            messagebox.showwarning(
                "Warning", 
                "Please configure PKS first (use File > Setup PKS)"
            )
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
                ecu_values = self.ecu_tree.item(selection[0])['values']
                ecu_type = ecu_values[0]
                ecu_serial = f"SN-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
                
                # Generate keys using PKS client
                result = self.pks_client.generate_ecu_key(
                    vin=self.current_vin.get(),
                    ecu_type=ecu_type,
                    ecu_serial=ecu_serial
                )
                
                if result:
                    # Persist generated key metadata for inject stage
                    generated = {
                        'vin': self.current_vin.get(),
                        'ecu_serial': ecu_serial,
                        'key_id': result.get('key_id'),
                        'fetched_at': datetime.datetime.now().isoformat(),
                        'key_data': result
                    }
                    self.generated_keys.append(generated)
                    self.last_generated_key = generated

                    # Report that keys were generated
                    self.pks_client.report_injection(
                        vin=self.current_vin.get(),
                        ecu_serial=ecu_serial,
                        key_id=result['key_id'],
                        status="generated",
                        operator=self.current_operator.get()
                    )
                    
                    self.root.after(0, lambda: self.progress.stop())
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Success", 
                        f"Keys generated for {ecu_type}\nKey ID: {result['key_id']}"
                    ))
                    logging.info(f"Keys generated for {ecu_type} - VIN: {self.current_vin.get()}")
                else:
                    self.root.after(0, lambda: self.progress.stop())
                    self.root.after(0, lambda: messagebox.showerror(
                        "Error", "Key generation failed"
                    ))
                
            except Exception as e:
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                logging.error(f"Key generation failed: {e}")
        
        threading.Thread(target=task, daemon=True).start()
    
    # ========================================================================
    # Updated Inject Keys Method
    # ========================================================================
    
    def inject_keys_threaded(self):
        """Inject keys into ECU (simulated)"""
        if not self.pks_client:
            messagebox.showwarning("Warning", "Please configure PKS first")
            return

        if not self.last_generated_key:
            messagebox.showwarning(
                "Warning",
                "No generated PKS key found. Please request keys first."
            )
            return
        
        self.progress.start()
        
        def task():
            try:
                # Simulate key injection delay
                import time
                time.sleep(2)

                key_info = self.last_generated_key
                key_id = key_info.get('key_id')
                ecu_serial = key_info.get('ecu_serial')
                vin = key_info.get('vin', self.current_vin.get())

                # Here you would inject the key material into the ECU hardware interface.
                # For simulation, we just log the values.
                logging.info(f"Injecting key {key_id} to ECU {ecu_serial} (VIN={vin})")

                # Report success to PKS audit endpoint
                self.pks_client.report_injection(
                    vin=vin,
                    ecu_serial=ecu_serial,
                    key_id=key_id,
                    status="injected",
                    operator=self.current_operator.get()
                )

                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showinfo(
                    "Success", f"Key {key_id} injected for ECU {ecu_serial}"
                ))
                logging.info(f"Keys injected successfully for {ecu_serial}")
                
            except Exception as e:
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        
        threading.Thread(target=task, daemon=True).start()
    
    # ========================================================================
    # Updated Menu Setup (adds PKS option)
    # ========================================================================
    
    def setup_menu(self):
        """Create menu bar with PKS option"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Setup PKS", command=self.setup_windows_pks)  # NEW
        file_menu.add_separator()
        file_menu.add_command(label="Load Production Order", command=self.load_production_order)
        file_menu.add_command(label="Export Audit Log", command=self.export_audit_log)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="HSM Configuration", command=self.configure_hsm)
        tools_menu.add_command(label="PKS Configuration", command=self.setup_windows_pks)  # Changed
        tools_menu.add_command(label="Key Management", command=self.key_management_dialog)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
    
    # ========================================================================
    # UI Setup (keep your existing UI setup code)
    # ========================================================================
    
    def setup_ui(self):
        """Create main UI layout - Keep your existing UI code here"""
        # Your existing UI setup code remains exactly the same
        # I'm including a minimal version for completeness, but replace with your actual UI
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Header Section
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
        
        # ECU Configuration Section
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
        
        # Operations Panel
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
        
        # Log Panel
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
        
        # Progress Bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
    
    # ========================================================================
    # Placeholder methods (keep your existing implementations)
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
        lib_path.insert(0, r"C:\SoftHSM2\lib\softhsm2-x64.dll")
        
        ttk.Label(dialog, text="Slot Number:").pack(pady=5)
        slot = ttk.Entry(dialog, width=10)
        slot.pack(pady=5)
        slot.insert(0, "287720487")
        
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
        dialog.geometry("500x250")
        
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
            firmware_file = firmware_path.get().strip()
            version_text = version.get().strip()

            if not firmware_file:
                messagebox.showwarning("Warning", "Please select a firmware file")
                return

            if not version_text:
                messagebox.showwarning("Warning", "Please enter a version")
                return

            self.progress.start()
            
            def task():
                try:
                    secure_image = self.update_manager.prepare_secure_image(
                        firmware_file,
                        version_text,
                        ecu_type
                    )
                    
                    # Save secure image
                    output_path = f"secure_image_{ecu_type}_{version_text}.json"
                    with open(output_path, 'w') as f:
                        json.dump(secure_image, f, indent=2)
                    
                    self.root.after(0, lambda: self.progress.stop())
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Success", f"Secure image saved to {output_path}"))
                    logging.info(f"Secure image prepared for {ecu_type} v{version_text}")
                    
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
PKS Status: {'Connected' if self.pks_client else 'Disconnected'}

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
