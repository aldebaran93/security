Quick Start
===========

Get PSMS up and running in 5 minutes.

Installation
~~~~~~~~~~~~

**Windows:**

.. code-block:: powershell

    # Clone or download the repository
    cd "c:\Embedded C\security"
    
    # Install dependencies
    pip install zeep python-pkcs11 lxml cryptography

**Linux/macOS:**

.. code-block:: bash

    cd security
    pip install zeep python-pkcs11 lxml cryptography

Running the Application
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    python pcks_pks_kms.py

A GUI window will open with the application interface.

Initial Configuration
~~~~~~~~~~~~~~~~~~~~~

1. **Configure HSM Connection**
   
   - Go to: **Tools** → **HSM Configuration**
   - Enter your PKCS#11 library path
   - Set the slot number and PIN
   - Click "Connect"

2. **Configure Production Key Server**
   
   - Go to: **Tools** → **PKS Configuration**
   - Enter WSDL URL
   - Upload client certificate and private key
   - Click "Connect"

3. **Add ECU Configuration**
   
   - Click "Add ECU" button
   - Enter ECU details:
     - ECU Type
     - Part Number
     - Hardware Version
     - Software Version
     - Security Level

Basic Workflow
~~~~~~~~~~~~~~

1. **Load Production Order** or enter VIN manually
2. **Request Keys from PKS** - Retrieves vehicle-specific keys
3. **Inject Keys into ECU** - Stores keys in ECU
4. **Prepare Secure Update** - Creates signed firmware image
5. **Flash Secure Image** - Updates ECU firmware
6. **Verify Installation** - Confirms update success
7. **Generate Audit Report** - Documents all operations

Example Production Order File
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a JSON file with the following structure:

.. code-block:: json

    {
      "vin": "WVWZZZ3CZ9E123456",
      "model": "ID.4",
      "production_date": "2024-01-15T10:30:00",
      "ecus": [
        {
          "type": "EngineControl",
          "part_number": "0ZS123456",
          "hw_version": "1.0",
          "sw_version": "1.2.3",
          "security_level": 3
        }
      ],
      "status": "pending"
    }

Load it using: **File** → **Load Production Order**

Troubleshooting
~~~~~~~~~~~~~~~

**Connection Issues:**

- Verify PKCS#11 library path is correct
- Check HSM device is connected
- Ensure PIN is correct

**SOAP Errors:**

- Verify WSDL URL is accessible
- Check certificates are valid
- Ensure mutual TLS is enabled

See :doc:`troubleshooting` for more help.
