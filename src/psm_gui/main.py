from security.src.psm_gui.production_security_gui import ProductionSecurityGUI
import tkinter as tk

# ============================================================================
# Main Application Entry Point
# ============================================================================

"""
Production Security Management GUI
Features:
- Secure ECU Update Management
- Production Key Server (SOAP) Integration with WS-Security
- HSM (PKCS#11) Integration for Key Operations
- VIN-to-Key Binding and Tracking
- Audit Logging and Reporting
"""

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