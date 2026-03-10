FAQ & Common Questions
======================

General Questions
~~~~~~~~~~~~~~~~~

**Q: What is the main purpose of PSMS?**

A: PSMS secures automotive production by managing cryptographic keys and ensuring only authorized firmware updates reach vehicles. It prevents unauthorized modifications to vehicle software.

**Q: Can PSMS work without an HSM?**

A: For testing/development, yes (using SoftHSM). For production, a physical HSM is recommended for security compliance and tamper protection.

**Q: How long does it take to secure one vehicle?**

A: Typically 10-15 minutes including key request, injection, firmware update, and verification. This varies with network latency and ECU count.

**Q: Does PSMS support multiple ECUs?**

A: Yes, PSMS handles vehicles with 2-20+ ECUs. Process each ECU sequentially or in parallel depending on your production line setup.

HSM Questions
~~~~~~~~~~~~~~

**Q: What if I lose my HSM PIN?**

A: The PIN cannot be recovered. You must reinitialize the HSM token, which will erase all stored keys. Maintain secure backups of HSM configuration.

**Q: Can I use multiple HSMs?**

A: Not simultaneously. PSMS connects to one HSM at a time. You can switch HSMs by reconfiguring the PKCS#11 library path.

**Q: How long do HSM keys last?**

A: Production typically rotate keys annually. Set reminders for certificate renewal before expiration.

**Q: Is SoftHSM suitable for production?**

A: No, SoftHSM stores keys unencrypted on disk. Use only for development/testing. For production, use certified hardware HSM (Thales, Gemalto, etc).

PKS Questions
~~~~~~~~~~~~~

**Q: What if the PKS is unreachable?**

A: PSMS cannot request keys. Implement fallback PKS or queue requests for retry. Maintain list of alternative PKS servers.

**Q: Can I request keys for vehicles not in PKS database?**

A: No, PKS validates all VINs. Contact PKS administrator to register new VINs before production runs.

**Q: How are vehicle-specific keys generated?**

A: The PKS uses the VIN as input to deterministic key derivation. Same VIN always produces same keys (within same time period).

**Q: What if a vehicle's keys expire?**

A: Request new keys from PKS. The new keys will be bound to the same VIN with extended expiry date.

Security Questions
~~~~~~~~~~~~~~~~~~

**Q: Are keys visible in memory?**

A: Keys in HSM never leave the device. Keys transmitted over network are encrypted. PSMS memory usage follows cryptographic best practices.

**Q: Can firmware be downgraded?**

A: The system signs firmware with timestamps. ECUs can be configured to reject older firmware versions.

**Q: What happens if someone steals a vehicle?**

A: Each vehicle has unique keys bound to its VIN. A stolen vehicle's keys cannot be used in unmodified form. OTA updates use PKS verification.

**Q: How is the audit trail protected?**

A: Audit logs are written to disk immediately with append-only semantics. Consider external audit log archival for compliance.

Troubleshooting Questions
~~~~~~~~~~~~~~~~~~~~~~~~

**Q: PSMS crashes when connecting to HSM?**

A: Check PKCS#11 library path is correct. Verify library architecture (32/64-bit) matches Python. Update PKCS#11 library.

**Q: PKS certificate validation fails?**

A: Ensure CA certificate is provided. Verify certificate chain is complete. Check system time is correct (affects certificate validity).

**Q: Firmware verification fails after flashing?**

A: Confirm firmware file is not corrupted. Verify ECU bootloader supports verification. Check signature algorithm matches ECU expectations.

**Q: Audit log file grows too large?**

A: Archive old logs regularly. Implement log rotation (keep last 30 days). Use external logging service for large deployments.

Production Questions
~~~~~~~~~~~~~~~~~~~

**Q: How do I scale to high-volume production?**

A: Multi-threading lets PSMS handle ~4-6 vehicles/hour with single thread. Parallel deployment uses multiple PSMS instances with centralized PKS.

**Q: Can I run PSMS on a headless server?**

A: GUI is Tkinter which requires display. For headless operation, refactor main business logic into API service (Flask/FastAPI).

**Q: How do I back up production data?**

A: Back up: HSM configuration, audit logs, certificates, production orders, firmware binaries. Use encrypted storage for backups.

**Q: What compliance standards does PSMS support?**

A: Follows ISO 26262 (functional safety), ISO 27001 (security), and automotive OEM requirements. Integrates with existing compliance frameworks.

Database Questions
~~~~~~~~~~~~~~~~~~

**Q: Can I use a database instead of JSON files?**

A: Yes, PSMS can be extended with SQLite/PostgreSQL backend. See advanced configuration guide for example.

**Q: How do I migrate existing production orders?**

A: Export from old system to JSON, then import into PSMS. Custom scripts can convert CSV/Excel to JSON format.

**Q: Can I archive historical orders?**

A: Yes, implement automatic archival of completed orders to archive database. Retain for compliance (typically 7+ years).

Performance Questions
~~~~~~~~~~~~~~~~~~~~

**Q: How much CPU/RAM does PSMS use?**

A: Minimal: ~5-10% CPU during operations, ~100-150 MB RAM. Primarily limited by network latency (waiting for PKS, ECU).

**Q: Can I process multiple vehicles simultaneously?**

A: The GUI is single-threaded, but background operations use threads. For true parallelism, run multiple PSMS instances.

**Q: What's the bottleneck in the workflow?**

A: Typically: PKS network latency (2-5s), ECU communication (3-5s per ECU), firmware flashing (5-10s). HSM operations are fastest (<1s).

Support Questions
~~~~~~~~~~~~~~~~

**Q: Where can I report security issues?**

A: Contact security team directly. Do not post security vulnerabilities publicly. Allow 90 days for remediation before disclosure.

**Q: Is source code available?**

A: The codebase is in Python. Review `/pcks_pks_kms.py` for implementation details. Documentation in `/docs/`.

**Q: How do I contribute improvements?**

A: See :doc:`contributing` for guidelines. Submit pull requests with test coverage and documentation.

Still Have Questions?
~~~~~~~~~~~~~~~~~~~

See related documentation:

- :doc:`troubleshooting` - Common issues and solutions
- :doc:`architecture` - System design details
- :doc:`workflow` - Step-by-step process
- :doc:`hsm_setup` - HSM configuration help
- :doc:`pks_integration` - PKS integration guide
