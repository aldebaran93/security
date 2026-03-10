References & Resources
======================

Standards & Specifications
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Automotive Security:**

- `ISO 26262 <https://www.iso.org/standard/43464.html>`_ - Functional Safety (IEC 61508 for automotive)
- `ISO/SAE 21434 <https://www.iso.org/standard/70713.html>`_ - Cybersecurity and Privacy Protection
- `J3061 <https://www.sae.org/standards/content/j3061_201601/>`_ - SAE Cybersecurity Guidebook

**Cryptography:**

- `RFC 5280 <https://tools.ietf.org/html/rfc5280>`_ - Internet X.509 Public Key Infrastructure
- `FIPS 140-2 <https://csrc.nist.gov/publications/detail/fips/140/2>`_ - Security Requirements for Cryptographic Modules
- `NIST SP 800-175B <https://csrc.nist.gov/publications/detail/sp/800-175/b>`_ - Guideline for Cryptographic Algorithms

**Web Services & XML:**

- `OASIS WS-Security <http://docs.oasis-open.org/wss/>`_ - Web Services Security Standard
- `SOAP 1.2 <https://www.w3.org/TR/soap12/>`_ - Simple Object Access Protocol
- `XML Signature <https://www.w3.org/TR/xmldsig-core1/>`_ - XML Digital Signature

**TLS/PKI:**

- `RFC 5246 <https://tools.ietf.org/html/rfc5246>`_ - TLS 1.2
- `RFC 8446 <https://tools.ietf.org/html/rfc8446>`_ - TLS 1.3
- `RFC 6090 <https://tools.ietf.org/html/rfc6090>`_ - Fundamental ECC Algorithms

Python Libraries
~~~~~~~~~~~~~~~~

**Core Dependencies:**

- `zeep <https://docs.python-zeep.org/>`_ - SOAP client (WS-Security support)
- `python-pkcs11 <https://github.com/danni/python-pkcs11>`_ - PKCS#11 interface
- `cryptography <https://cryptography.io/>`_ - Cryptographic recipes
- `requests <https://docs.python-requests.org/>`_ - HTTP library
- `lxml <https://lxml.de/>`_ - XML processing

**Optional Libraries:**

- `SQLAlchemy <https://www.sqlalchemy.org/>`_ - Database ORM
- `Flask <https://flask.palletsprojects.com/>`_ - Web framework (for API)
- `pytest <https://pytest.org/>`_ - Testing framework
- `black <https://black.readthedocs.io/>`_ - Code formatter

Hardware
~~~~~~~~

**Recommended HSM Devices:**

+-------------------+----------------------------------+------------------+
| Device            | Provider                         | Automotive Grade |
+===================+==================================+==================+
| Thales Luna       | Gemalto/Thales                  | Yes              |
+-------------------+----------------------------------+------------------+
| SafeNet Luna      | Thales                          | Yes              |
+-------------------+----------------------------------+------------------+
| YubiHSM           | Yubico                          | Limited          |
+-------------------+----------------------------------+------------------+
| SoftHSM           | OpenDNSSEC Project              | No (dev only)    |
+-------------------+----------------------------------+------------------+

**Secure Communication:**

- Network HSM bridges (e.g., Luna Network HSM)
- Encrypted USB hardware tokens
- High-assurance network infrastructure

Documentation & Guides
~~~~~~~~~~~~~~~~~~~~~

**PKCS#11:**

- `PKCS#11 Specification <http://docs.oasis-open.org/pkcs11/pkcs11-base/>`_ - Cryptoki standard
- `Thales Luna PKCS#11 <https://thalesdocs.com/gphsm/hsm/5.4.0/index.html>`_ - Luna-specific docs

**Related Documentation:**

- This guide (PSMS documentation in `/docs/`)
- API reference (auto-generated from docstrings)
- Vendor documentation for your specific HSM

Tools & Utilities
~~~~~~~~~~~~~~~~~

**Development Tools:**

.. code-block:: bash

    # Install development tools
    pip install sphinx sphinx_rtd_theme pytest black mypy pylint
    pip install bandit  # Security linting
    pip install coverage  # Code coverage

**Testing:**

.. code-block:: bash

    # View test coverage
    pytest --cov=pcks_pks_kms tests/
    coverage html

**Certificate Management:**

.. code-block:: bash

    # OpenSSL for certificate operations
    openssl x509 -text -noout -in cert.pem
    openssl req -new -key private.key -out csr.pem

**Security Scanning:**

.. code-block:: bash

    # Check for vulnerabilities
    bandit -r pcks_pks_kms.py
    pip-audit

Related Projects
~~~~~~~~~~~~~~~~

**Similar Security Solutions:**

- `Uptane <https://uptane.github.io/>`_ - Secure software update framework
- `OpenEMS <https://openems.readthedocs.io/>`_ - Electromagnetic simulation (reference for docs)
- `Trusted Platform Module (TPM) <https://trustedcomputinggroup.org/>`_ - Hardware security

**Integration Examples:**

- CAN bus communication libraries
- UEFI/BIOS security modules
- ECU flashing tools

Performance Benchmarks
~~~~~~~~~~~~~~~~~~~~~

**Typical Performance Metrics:**

+------------------------+------------+----------+
| Operation              | Time       | Notes    |
+========================+============+==========+
| HSM Connect            | 100ms      | Per session |
| HSM Key Generation     | 500ms      | RSA-2048 |
| PKCS#11 Signing        | 200ms      | Per signature |
| SOAP Key Request       | 2-5s       | Network dependent |
| Firmware Hash (100MB)  | 500ms      | SHA-256 |
| ECU Key Injection      | 2-3s       | Per ECU |
| Firmware Flash (5MB)   | 5-10s      | Baud rate dependent |
+------------------------+------------+----------+

**Optimization Tips:**

- Reuse HSM session for multiple operations
- Cache frequently requested keys
- Use connection pooling for SOAP
- Batch ECU operations where possible

Best Practices
~~~~~~~~~~~~~~

**Security:**

- Use strong PINs (16+ characters, alphanumeric)
- Rotate HSM keys annually
- Enable audit logging
- Restrict physical HSM access
- Use TLS 1.2+

**Operations:**

- Maintain backup HSM
- Document all procedures
- Implement change control
- Monitor HSM/PKS health
- Archive audit logs

**Development:**

- Use type hints
- Write unit tests
- Document all functions
- Follow PEP 8
- Use git for version control

Industry Contacts
~~~~~~~~~~~~~~~~~

**Standards Bodies:**

- `SAE International <https://www.sae.org/>`_ - Automotive standards
- `NIST <https://csrc.nist.gov/>`_ - Cryptography standards
- `OASIS <https://www.oasis-open.org/>`_ - Web standards

**Security Organizations:**

- `ICS CERT <https://www.cisa.gov/>`_ - Cybersecurity alerts
- `ENISA <https://www.enisa.europa.eu/>`_ - European cybersecurity agency

**Hardware Vendors:**

- Thales (Luna HSM)
- Gemalto (now Thales)
- Yubico (YubiHSM)

Online Resources
~~~~~~~~~~~~~~~~

**Documentation:**

- `Python Documentation <https://docs.python.org/3/>`_
- `Cryptography.io <https://cryptography.io/>`_
- `PKCS#11 Specification <http://docs.oasis-open.org/pkcs11/>`_

**Learning:**

- `NIST Cybersecurity Framework <https://www.nist.gov/cyberframework>`_
- `SANS Security Training <https://www.sans.org/>`_
- `ISC2 Certifications <https://www.isc2.org/>`_

**Communities:**

- Stack Overflow (tag: cryptography, pkcs11)
- GitHub Issues (this project)
- Python-Cryptography mailing list

Changelog
~~~~~~~~~

**Version 1.0.0** (Current)

- Initial release
- HSM PKCS#11 integration
- SOAP/WS-Security PKS client
- Secure firmware update manager
- Audit logging

**Planned Features:**

- REST API interface
- Database backend
- Docker containerization
- Key rotation automation
- Enhanced reporting

Support & Contact
~~~~~~~~~~~~~~~~

**For Questions:**

- See :doc:`faq`
- Check :doc:`troubleshooting`
- Review :doc:`architecture`

**For Security Issues:**

- Contact security team
- Follow responsible disclosure
- Allow 90 days for patch

**For Features/Bugs:**

- Open GitHub issue
- Reference existing documentation
- Provide details and logs
