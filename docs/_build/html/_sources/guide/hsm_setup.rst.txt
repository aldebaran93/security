HSM Setup and Configuration
===========================

Hardware Security Module Overview
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An HSM is a dedicated cryptographic processor that provides:

- Tamper-resistant key storage
- Certified encryption operations
- Access control and audit logging
- FIPS 140-2 compliance

Supported HSM Devices
~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1

   * - Device
     - PKCS#11 Library
     - Notes
   * - Thales Luna
     - crystoki.dll/so
     - Enterprise HSM
   * - Gemalto/SafeNet
     - GTwcsm.dll/so
     - Common automotive grade
   * - YubiHSM
     - yubihsm-pkcs11.dll
     - Cost-effective
   * - SoftHSM
     - softhsm2.dll/so
     - Testing/development

Setup Instructions
~~~~~~~~~~~~~~~~~~

**Using SoftHSM 2 (for testing/development)**

1. **Install SoftHSM:**

   *Windows:*
   
   .. code-block:: powershell
   
       choco install softhsm
   
   *Linux:*
   
   .. code-block:: bash
   
       sudo apt install softhsm2
   
   *macOS:*
   
   .. code-block:: bash
   
       brew install softhsm

2. **Initialize Token:**

   .. code-block:: bash
   
       softhsm2-util --init-token --slot 0 --label "PSMS" --pin 1234 --so-pin 1234

3. **Locate Library:**

   - *Windows:* ``C:\Program Files\SoftHSM2\lib\softhsm2.dll``
   - *Linux:* ``/usr/lib/softhsm/libsofthsm2.so``
   - *macOS:* ``/usr/local/lib/softhsm/libsofthsm2.dylib``

4. **Configure in PSMS:**

   - Go to **Tools** → **HSM Configuration**
   - Enter the library path from above
   - Slot: ``0``
   - PIN: ``1234`` (or your chosen PIN)
   - Click "Connect"

**Using Production HSM (Thales Luna)**

1. **Install Luna Client:**

   Download from Thales support portal and install

2. **Initialize HSM:**

   .. code-block:: bash
   
       lunacm
       # At prompt: open session
       # Initialize: hsm login
       # Create partition if needed

3. **Get Slot Number:**

   .. code-block:: bash
   
       lunacm
       # hsm showinfo

4. **Find Library Path:**

   - Windows: ``C:\Program Files (x86)\Thales\CryptoComply\Luna\lib\crystoki.dll``
   - Linux: Usually installed in system path

5. **Configure in PSMS:**

   - **HSM Configuration** dialog
   - Use crystoki.dll path and correct slot
   - Use your Luna PIN

HSM Operations
~~~~~~~~~~~~~~

**Key Generation:**

The system supports:

- **RSA-2048** - Primary algorithm for signatures
- **RSA-4096** - High-security variant
- **AES-128/256** - Symmetric encryption

Keys generated in HSM are:

- Never exported from HSM
- Bound to specific HSM token
- Protected by PIN
- Auditable

**Key Storage:**

.. code-block:: python

    # Generate key pair
    keys = hsm.generate_key_pair(
        key_label="production_key_001",
        key_type="RSA",
        key_size=2048
    )
    
    # Keys are stored in HSM
    # Only public key is returned
    print(keys['public_key_pem'])

**Signing Operations:**

.. code-block:: python

    # Sign firmware metadata
    signature = hsm.sign_data(
        key_label="production_key_001",
        data=firmware_metadata.encode()
    )

Troubleshooting HSM Connection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Issue: "Failed to connect to HSM"**

1. Verify PKCS#11 library path is correct:
   
   .. code-block:: python
   
       import os
       print(os.path.exists(lib_path))

2. Ensure library has correct architecture (32/64-bit)

3. For Windows, verify Visual C++ Redistributable installed

**Issue: "Slot not found"**

1. Check HSM is connected/powered on

2. List available slots:
   
   .. code-block:: bash
   
       # For SoftHSM
       softhsm2-util --show-slots

3. Try slot 0 first, then increment

**Issue: "PIN verification failed"**

1. Verify PIN is correct (case-sensitive)

2. Check if token is locked (too many attempts)

3. For SoftHSM, default PIN is often "1234"

**Issue: "Token not initialized"**

1. Initialize token:
   
   .. code-block:: bash
   
       softhsm2-util --init-token --slot 0 --label "Test"

2. Set PIN when prompted

HSM Security Best Practices
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **PIN Management:**
   
   - Use strong, random PINs (16+ characters)
   - Change regularly (annually minimum)
   - Never hardcode in source
   - Store securely (environment variables)

2. **Key Lifecycle:**
   
   - Rotate keys periodically
   - Archive old keys securely
   - Track key usage in audit logs
   - Retire keys when no longer needed

3. **Physical HSM:**
   
   - Keep in physically secure location
   - Limit access to authorized personnel
   - Monitor for tampering alerts
   - Maintain backup HSM

4. **Disaster Recovery:**
   
   - Export public keys for recovery
   - Maintain HSM backups
   - Document token configuration
   - Test recovery procedures

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

Set sensitive configuration via environment:

.. code-block:: bash

    # Windows
    set HSM_PIN=1234
    set PKCS11_LIB=C:\Program Files\SoftHSM2\lib\softhsm2.dll
    
    # Linux/macOS
    export HSM_PIN=1234
    export PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so

Access from code:

.. code-block:: python

    import os
    hsm = HSMManager(
        pkcs11_lib_path=os.environ.get('PKCS11_LIB'),
        pin=os.environ.get('HSM_PIN')
    )
