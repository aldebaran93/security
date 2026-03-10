Production Security Management System Documentation
=====================================================

An automotive security solution for secure ECU updates, production key management, and HSM integration.

**Core Features:**

- 🔐 **Secure ECU Update Management** - Cryptographically signed firmware updates with verification
- 🔑 **Production Key Server (SOAP)** - WS-Security integration with mutual TLS authentication  
- 🛡️ **HSM (PKCS#11) Integration** - Hardware-backed key storage and cryptographic operations
- 🚗 **VIN-to-Key Binding** - Vehicle identification number to key mapping and lifecycle management
- 📋 **Audit Logging** - Comprehensive audit trail and compliance reporting

.. toctree::
   :maxdepth: 3
   :caption: Getting Started

   guide/introduction
   guide/quick_start
   guide/requirements

.. toctree::
   :maxdepth: 3
   :caption: User Guide

   guide/architecture
   guide/hsm_setup
   guide/pks_integration
   guide/workflow

.. toctree::
   :maxdepth: 3
   :caption: Tutorials

   guide/tutorial_basic
   guide/tutorial_advanced

.. toctree::
   :maxdepth: 3
   :caption: API Reference

   api/modules

.. toctree::
   :maxdepth: 2
   :caption: Troubleshooting

   guide/faq
   guide/troubleshooting

.. toctree::
   :maxdepth: 2
   :caption: Additional Resources

   guide/contributing
   guide/references

Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

