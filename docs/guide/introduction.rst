Introduction
=============

Welcome to the Production Security Management System (PSMS) documentation.

Overview
--------

The Production Security Management System is a comprehensive solution designed for automotive manufacturing to secure ECU (Electronic Control Unit) firmware updates and manage cryptographic keys throughout the vehicle production lifecycle.

What is PSMS?
~~~~~~~~~~~~~

PSMS is a Python-based application that integrates with:

- **Hardware Security Modules (HSM)** - PKCS#11 compliant devices for secure key storage
- **Production Key Servers (PKS)** - SOAP-based web services for key distribution
- **Automotive ECUs** - Electronic control units requiring secure firmware updates

System Architecture
~~~~~~~~~~~~~~~~~~~

The system consists of four main components:

1. **HSM Manager** - Interfaces with hardware security modules for key operations
2. **Production Key Server Client** - Handles SOAP/WS-Security communication
3. **Secure Update Manager** - Prepares and verifies firmware images
4. **GUI Application** - User-friendly interface for all operations

Use Cases
~~~~~~~~~

- Secure firmware distribution to production vehicles
- Vehicle-specific key binding (VIN-to-Key mapping)
- Audit trail and compliance reporting
- Key lifecycle management
- Production order management

Key Features
~~~~~~~~~~~~

.. list-table::
   :header-rows: 1

   * - Feature
     - Description
   * - **Mutual TLS**
     - Client and server authentication
   * - **XML Signatures**
     - WS-Security implementation
   * - **PKCS#11**
     - Hardware security module integration
   * - **Audit Logging**
     - Complete operation tracking
   * - **Encryption**
     - RSA and AES support

Next Steps
~~~~~~~~~~

- :doc:`quick_start` - Get up and running in 5 minutes
- :doc:`requirements` - System requirements and dependencies
- :doc:`architecture` - Detailed architecture overview
