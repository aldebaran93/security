Basic Tutorial
==============

Getting Your First Vehicle Secured
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This tutorial walks you through securing one vehicle from production order to deployment.

Prerequisites
~~~~~~~~~~~~~

- PSMS installed and running
- HSM configured (see :doc:`hsm_setup`)
- PKS connection configured (see :doc:`pks_integration`)
- Sample production order JSON file

Step 1: Load the Production Order
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Create a test order file** (``test_order.json``):

.. code-block:: json

    {
      "vin": "TEST123456789012",
      "model": "TestVehicle",
      "production_date": "2024-03-10T09:00:00",
      "ecus": [
        {
          "type": "EngineControl",
          "part_number": "ECU001",
          "hw_version": "1.0",
          "sw_version": "1.0.0",
          "security_level": 2
        }
      ],
      "status": "pending"
    }

**Load into PSMS:**

1. Click **File** → **Load Production Order**
2. Browse to ``test_order.json``
3. Click Open
4. You should see the VIN populated and ECU listed

**Verify:** The ECU tree shows one row with your ECU details.

Step 2: Request Keys from PKS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Send key request:**

1. Select the ECU in the tree (click on "EngineControl")
2. Click **"1. Request Keys from PKS"** button
3. PSMS shows progress bar (spinning circle)
4. Wait for confirmation dialog

**What to expect:**

.. code-block:: text

    [10:00:00] INFO: Keys requested for EngineControl - VIN: TEST123456789012
    [10:00:02] INFO: Keys received for EngineControl
    [10:00:02] INFO: Key ID: KEY-20240310-001
    [10:00:02] INFO: Expiry: 2025-03-10
```

Dialog appears: **"Success - Keys received for EngineControl - Key ID: KEY-20240310-001"**

Click **OK**.

Step 3: Inject Keys into ECU (Simulated)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this demo, we'll simulate key injection:

1. Click **"2. Inject Keys into ECU"** button
2. System shows progress (simulates 2-second operation)
3. Confirmation dialog appears

**Log shows:**

.. code-block:: text

    [10:01:00] INFO: Keys injected: KeyInjectionRecord(vin='TEST123456...')
    [10:01:00] INFO: Reported injection to PKS: Success
    Success - Keys injected successfully
```

Click **OK** in the dialog.

Step 4: Prepare Secure Firmware Image
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before doing this, create a test firmware file:

**Create dummy firmware** (``test_firmware.bin``):

.. code-block:: bash

    # Windows - create 1MB test file
    fsutil file createnew test_firmware.bin 1000000
    
    # Linux/macOS
    dd if=/dev/zero of=test_firmware.bin bs=1M count=1

**Prepare image:**

1. Click **"3. Prepare Secure Update"** button
2. Dialog opens for firmware selection
3. Click **Browse...** button
4. Select ``test_firmware.bin``
5. Enter version: ``1.0.1``
6. Click **Prepare Image**
7. Progress bar shows operation
8. Confirmation dialog: **"Secure image saved to secure_image_EngineControl_1.0.1.json"**

The file is created in your working directory.

**Verify:** Check file creation:

.. code-block:: bash

    ls -la secure_image_*.json
    
    # Or in Windows Explorer
    #   secure_image_EngineControl_1.0.1.json

Step 5: Flash Firmware (Simulated)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Click **"4. Flash Secure Image"** button
2. Progress bar shows (~3 seconds)
3. Success message appears: **"Update flashed successfully"**

**Log shows:**

.. code-block:: text

    [10:02:00] INFO: Secure update flashed successfully

Step 6: Verify Installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Click **"5. Verify Installation"** button
2. Dialog shows: **"Installation verification complete"**

Step 7: Generate Audit Report
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Click **"Generate Audit Report"** button
2. Report is created with filename: ``audit_report_20240310_100230.txt``
3. Success message: **"Report saved to audit_report_20240310_100230.txt"**

**View the report:**

.. code-block:: bash

    cat audit_report_*.txt
    
    # Or open in text editor

**Report content example:**

.. code-block:: text

    Production Security Audit Report
    ================================
    Generated: 2024-03-10 10:02:30
    Operator: YourUsername
    VIN: TEST123456789012
    
    HSM Status: Connected
    PKS Status: Connected
    
    ECU Configuration:
    ------------------
    
    - Type: EngineControl, Part: ECU001, Security: 2
    
    Recent Operations:
    ------------------

Complete! Your vehicle has been secured from production to deployment.

Troubleshooting This Tutorial
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Keys Request Failed:**

1. Verify PKS is connected (green indicator)
2. Check network connectivity
3. Review certificates in PKS Configuration

**Key Injection Failed:**

1. In demo mode, this should not fail
2. If it does, check HSM connection

**Image Preparation Failed:**

1. Verify firmware file exists and is readable
2. Check HSM is connected
3. Ensure you have write permissions

**No Audit Report Created:**

1. Check you have write permissions in current directory
2. Ensure timestamp in filename is valid

Next Steps
~~~~~~~~~~

- Explore :doc:`tutorial_advanced` for real ECU integration
- Review :doc:`workflow` for production procedures
- Learn about :doc:`hsm_setup` for security configuration
