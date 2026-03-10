Requirements
=============

System Requirements
~~~~~~~~~~~~~~~~~~~

**Hardware:**

- CPU: Intel/AMD x86-64 processor
- RAM: 4 GB minimum, 8 GB recommended
- Storage: 500 MB for application and dependencies
- Network: Internet connection for PKS communication

**Operating Systems:**

- Windows 7 SP1 or later (64-bit)
- Linux: Ubuntu 18.04 LTS or later, CentOS 7+
- macOS 10.13 or later

**HSM Hardware (Optional):**

- PKCS#11 compatible hardware security module
- Software HSM (SoftHSM) for testing
- Compatible with:
  - Thales Luna
  - Gemalto/SafeNet
  - YubiHSM
  - SoftHSM 2

Software Dependencies
~~~~~~~~~~~~~~~~~~~~

**Python Version:**

.. list-table::
   :header-rows: 1

   * - Component
     - Version
     - Purpose
   * - Python
     - 3.8+
     - Core runtime
   * - pip
     - Latest
     - Package manager
   * - Virtual Environment
     - Python venv
     - Dependency isolation

**Required Packages:**

.. list-table::
   :header-rows: 1

   * - Package
     - Version
     - Purpose
   * - zeep
     - 4.0+
     - SOAP client
   * - python-pkcs11
     - 0.7.0+
     - HSM integration
   * - cryptography
     - 3.4+
     - Cryptographic operations
   * - lxml
     - 4.6+
     - XML processing
   * - requests
     - 2.25+
     - HTTP client

**Optional Packages for Development:**

.. list-table::
   :header-rows: 1

   * - Package
     - Purpose
   * - sphinx
     - Documentation generation
   * - sphinx_rtd_theme
     - Read the Docs theme
   * - pytest
     - Testing framework
   * - black
     - Code formatter

Installation
~~~~~~~~~~~~

**Step 1: Python Installation**

Download from https://www.python.org/downloads/ (3.8 or later)

.. code-block:: bash

    python --version

**Step 2: Create Virtual Environment**

.. code-block:: bash

    python -m venv venv
    
    # Windows
    venv\Scripts\activate
    
    # Linux/macOS
    source venv/bin/activate

**Step 3: Install Dependencies**

.. code-block:: bash

    pip install --upgrade pip setuptools wheel
    pip install zeep python-pkcs11 lxml cryptography requests

**Step 4: Verify Installation**

.. code-block:: bash

    python pcks_pks_kms.py

GUI Configuration Requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**For HSM Integration:**

1. PKCS#11 Library (e.g., softhsm2.dll on Windows)
2. HSM slot number
3. User PIN for HSM access
4. Initialized token on HSM

**For PKS (Production Key Server):**

1. WSDL file or URL
2. Client certificate (PEM format)
3. Private key (PEM format)
4. CA certificate for server verification

Security Considerations
~~~~~~~~~~~~~~~~~~~~~~

1. **Private Keys** - Never store in version control
2. **Credentials** - Use environment variables when possible
3. **Network** - Always use TLS for communication
4. **Audit Logs** - Archive regularly for compliance
5. **HSM PIN** - Use strong, random PIN

System Access
~~~~~~~~~~~~~

**Read:** Firmware files, configuration files
**Write:** Audit logs, production orders, generated images
**Network:** PKS endpoint, optional remote HSM
