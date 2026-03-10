Production Workflow
===================

End-to-End Process
~~~~~~~~~~~~~~~~~~

This section describes the complete workflow from production order to vehicle deployment.

Phase 1: Order Reception
~~~~~~~~~~~~~~~~~~~~~~~~

**1.1 Load Production Order**

- Production planning sends order (JSON file)
- File contains: VIN, ECU list, software versions
- Load via: **File** → **Load Production Order**

**Example Order:**

.. code-block:: json

    {
      "vin": "WVWZZZ3CZ9E123456",
      "model": "ID.Buzz",
      "production_date": "2024-03-10T09:00:00",
      "ecus": [
        {
          "type": "EngineControl",
          "part_number": "0ZS123456",
          "hw_version": "2.1",
          "sw_version": "2.3.1",
          "security_level": 3
        },
        {
          "type": "InfotainmentSystem",
          "part_number": "0ZS789012",
          "hw_version": "3.0",
          "sw_version": "4.1.2",
          "security_level": 2
        }
      ],
      "status": "pending"
    }

**1.2 Verify ECU Configuration**

- Review ECU list in GUI
- Confirm all ECUs are present
- Add missing ECUs manually if needed
- Verify security levels are correct

Phase 2: Key Distribution
~~~~~~~~~~~~~~~~~~~~~~~~~

**2.1 Request Keys from PKS**

.. code-block:: bash

    1. Select ECU from list
    2. Click "Request Keys from PKS"
    3. System contacts production key server
    4. Server generates vehicle-specific keys
    5. Keys encrypted and transmitted

**What happens in background:**

.. code-block:: python

    # PSMS contacts PKS for this VIN
    keys = pks.request_ecu_keys(
        vin="WVWZZZ3CZ9E123456",
        ecu_type="EngineControl",
        ecu_serial="SN-20240310-001"
    )
    
    # PKS validates: VIN exists, authorized, correct ECU type
    # Returns vehicle-specific keys with expiry

**2.2 Verify Key Receipt**

- Confirm popup message shows key ID
- Log shows successful reception
- Keys are now stored locally (encrypted)

**Expected log message:**

.. code-block:: text

    [INFO] Keys received for EngineControl - VIN: WVWZZZ3CZ9E123456
    [INFO] Key ID: KEY-20240310-001
    [INFO] Expiry: 2025-03-10
```

Phase 3: Key Injection
~~~~~~~~~~~~~~~~~~~~~~

**3.1 Inject Keys into ECU**

.. code-block:: bash

    1. Ensure ECU is connected via CAN bus
    2. Click "Inject Keys into ECU"
    3. PSMS communicates with ECU bootloader
    4. Keys are securely transferred
    5. ECU stores keys in secure memory

**Key injection sequence:**

.. code-block:: text

    PSMS Security Processor
         │
         ├─ Lock ECU bootloader
         ├─ Transmit encryption key (AES-256)
         ├─ Transmit authentication key (HMAC)
         ├─ Transmit certificate
         ├─ ECU stores keys
         └─ Unlock bootloader

**3.2 Report Injection Status**

- PSMS automatically reports to PKS
- Status: "success" or "failed"
- PKS records in audit trail
- Log shows completion timestamp

Phase 4: Firmware Update
~~~~~~~~~~~~~~~~~~~~~~~~

**4.1 Prepare Secure Image**

.. code-block:: bash

    1. Click "Prepare Secure Update"
    2. Select firmware file (binary)
    3. Enter version number
    4. PSMS creates signed package

**What PSMS does:**

.. code-block:: python

    # Calculate firmware hash
    fw_hash = sha256(firmware_data)
    
    # Create metadata
    metadata = {
        'ecu_type': 'EngineControl',
        'version': '2.3.1',
        'timestamp': '2024-03-10T10:00:00',
        'firmware_hash': base64(fw_hash)
    }
    
    # Sign with HSM private key
    signature = hsm.sign_data('fw_signing_key', json.dumps(metadata))
    
    # Package everything
    secure_image = {
        'metadata': metadata,
        'signature': base64(signature),
        'firmware': base64(firmware_data)
    }

**4.2 Flash Secure Image**

.. code-block:: bash

    1. Click "Flash Secure Image"
    2. Select previously prepared image
    3. ECU verifies signature using public key
    4. ECU verifies firmware hash
    5. If valid, ECU flashes firmware
    6. ECU reboots and runs new firmware

**Hardware flow:**

.. code-block:: text

    Secure Image File
         │
         ▼
    ECU Bootloader
         ├─ Load public key from secure storage
         ├─ Verify image signature
         ├─ Calculate Hash(firmware binary)
         ├─ Compare with metadata hash
         └─ If OK: Program flash memory

Phase 5: Verification
~~~~~~~~~~~~~~~~~~~~

**5.1 Verify Installation**

.. code-block:: bash

    1. Click "Verify Installation"
    2. PSMS polls ECU for version
    3. Compares with expected version
    4. Confirms installation success

**5.2 Generate Audit Report**

Click "Generate Audit Report" to create comprehensive documentation:

- VIN and timestamps
- All operations performed
- Operator names
- Success/failure status
- Key IDs used
- Firmware versions
- AES-256 encrypted download

**Sample report:**

.. code-block:: text

    Production Security Audit Report
    ================================
    Generated: 2024-03-10 15:30:00
    Operator: John.Smith
    VIN: WVWZZZ3CZ9E123456
    
    HSM Status: Connected
    PKS Status: Connected
    
    ECU Configuration:
    - Type: EngineControl
      Part: 0ZS123456
      Security Level: 3
    
    Recent Operations:
    [10:00] Keys requested from PKS
    [10:05] Keys injected into ECU (ID: KEY-20240310-001)
    [10:10] Firmware v2.3.1 prepared (size: 2.5 MB)
    [10:15] Firmware flashed successfully
    [10:20] Installation verified - PASS

Error Handling
~~~~~~~~~~~~~~

**If Key Request Fails:**

1. Check PKS connection
2. Verify VIN exists in system
3. Confirm authorization
4. Review PKS audit logs
5. Retry operation

**If Key Injection Fails:**

1. Verify ECU is powered and connected
2. Check CAN bus communication
3. Ensure HSM is accessible
4. Review ECU bootloader logs
5. Attempt recovery/retry

**If Firmware Flash Fails:**

1. Verify image signature is valid
2. Check firmware file integrity
3. Confirm ECU bootloader is functional
4. Verify sufficient flash memory
5. Retry from beginning

Timeline Example
~~~~~~~~~~~~~~~~

For a typical vehicle production:

.. code-block:: text

    09:00  Vehicle arrives at security station
    09:05  Production order loaded
    09:10  Keys requested from PKS (2 min delay)
    09:12  Keys received for EngineControl
    09:15  Keys received for Infotainment
    09:20  Keys injected (1 min per ECU)
    09:22  All keys injected successfully
    09:30  Firmware images prepared (5 min)
    09:35  Flashing begins
    09:55  All ECUs updated
    10:00  Verification complete
    10:05  Audit report generated
    10:10  Vehicle released to next station

Total time: ~1 hour for typical multi-ECU vehicle
