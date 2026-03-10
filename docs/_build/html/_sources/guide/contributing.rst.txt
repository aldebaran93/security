Contributing
=============

How to Contribute
~~~~~~~~~~~~~~~~

We welcome contributions including bug reports, feature requests, documentation improvements, and code changes.

Development Setup
~~~~~~~~~~~~~~~~~

**1. Clone the Repository:**

.. code-block:: bash

    git clone https://github.com/yourusername/psms.git
    cd psms

**2. Install Development Dependencies:**

.. code-block:: bash

    pip install -r requirements-dev.txt

This includes: pytest, black, flake8, mypy, sphinx

**3. Create Feature Branch:**

.. code-block:: bash

    git checkout -b feature/my-feature

Code Style
~~~~~~~~~~

We follow PEP 8 with automatic formatting:

.. code-block:: bash

    black pcks_pks_kms.py
    flake8 pcks_pks_kms.py

Type hints are required:

.. code-block:: python

    def sign_data(self, key_label: str, data: bytes) -> bytes:
        """Sign data using HSM private key."""
        pass

Documentation
~~~~~~~~~~~~~~

All public functions need docstrings:

.. code-block:: python

    def request_ecu_keys(self, vin: str, ecu_type: str, 
                        ecu_serial: str) -> Dict[str, Any]:
        """Request ECU keys from Production Key Server.
        
        Sends SOAP request to PKS with WS-Security headers.
        Keys are vehicle-specific and time-limited.
        
        Args:
            vin: Vehicle Identification Number (17 chars)
            ecu_type: Type of ECU (e.g., 'EngineControl')
            ecu_serial: ECU serial number
            
        Returns:
            Dictionary containing:
            - encryption_key: AES key (base64)
            - authentication_key: HMAC key (base64)  
            - certificate: X.509 cert (base64)
            - key_id: Unique key identifier
            - expiry: Expiration date (ISO 8601)
            
        Raises:
            ConnectionError: If PKS is unreachable
            SOAPFault: If PKS rejects request
            
        Example:
            >>> keys = pks.request_ecu_keys(
            ...     "WVWZZZ3CZ9E123456",
            ...     "EngineControl",
            ...     "SN-123456"
            ... )
            >>> print(keys['key_id'])
            KEY-20240310-001
        """

Testing
~~~~~~~

Write tests for all new functionality:

.. code-block:: python

    import pytest
    from unittest.mock import Mock, patch
    
    class TestHSMManager:
        @pytest.fixture
        def hsm_manager(self):
            return HSMManager(
                pkcs11_lib_path="/path/to/lib.so",
                slot=0,
                pin="1234"
            )
        
        def test_sign_data_returns_bytes(self, hsm_manager):
            """Test that sign_data returns signature bytes"""
            with patch.object(hsm_manager, 'session'):
                result = hsm_manager.sign_data('key', b'data')
                assert isinstance(result, bytes)
        
        def test_sign_data_raises_on_invalid_key(self, hsm_manager):
            """Test error on nonexistent key"""
            with pytest.raises(Exception):
                hsm_manager.sign_data('invalid_key', b'data')

**Run Tests:**

.. code-block:: bash

    pytest tests/
    pytest tests/ --cov=pcks_pks_kms

Commit Guidelines
~~~~~~~~~~~~~~~~

Write clear commit messages:

.. code-block:: text

    Add HSM key rotation feature
    
    - Implements automatic key rotation every 90 days
    - Adds schedule-based rotation management
    - Updates audit logging for rotations
    
    Fixes #123

Good practices:

- One feature per commit
- Reference issue numbers
- Explain WHY, not just WHAT
- Keep commits focused

Pull Request Process
~~~~~~~~~~~~~~~~~~~

1. **Create Feature Branch:**

   .. code-block:: bash

       git checkout -b feature/my-feature

2. **Implement & Test:**

   .. code-block:: bash

       # Make changes
       pytest tests/
       black pcks_pks_kms.py

3. **Update Documentation:**

   - Add docstrings
   - Update relevant .rst files in docs/
   - Add examples if appropriate

4. **Push & Create PR:**

   .. code-block:: bash

       git push origin feature/my-feature
       # Create PR on GitHub

5. **PR Description Template:**

   .. code-block:: markdown

       ## Description
       Brief description of changes
       
       ## Type of Change
       - [ ] Bug fix
       - [ ] New feature
       - [ ] Documentation
       - [ ] Performance improvement
       
       ## Related Issue
       Fixes #123
       
       ## Testing
       - [ ] All tests pass
       - [ ] Added new tests
       - [ ] Manual testing completed
       
       ## Documentation
       - [ ] Updated relevant .rst files
       - [ ] Added/updated docstrings
       - [ ] Examples added

Review Process
~~~~~~~~~~~~~~

- Maintainers review code for:
  - Correctness
  - Security
  - Performance
  - Documentation
  - Test coverage
- Changes requested may need iteration
- Once approved, PR is merged

Security Issues
~~~~~~~~~~~~~~

**Do not** file public issues for security vulnerabilities.

Instead:

1. Contact security team directly
2. Describe issue without revealing exploit
3. Allow 90 days for patch before public disclosure
4. Responsible disclosure appreciated

Areas for Contribution
~~~~~~~~~~~~~~~~~~~~~

**Priority Areas:**

- [ ] Performance optimizations
- [ ] Enhanced error messages
- [ ] Additional unit tests
- [ ] Documentation improvements
- [ ] Integration with CI/CD
- [ ] Configuration management
- [ ] Metrics and monitoring

**Ideas:**

- Database backend support
- REST API interface
- Key rotation automation
- Advanced logging/reporting
- LDAP integration
- Docker containerization

Building Documentation Locally
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    cd docs/
    pip install sphinx sphinx_rtd_theme
    make html
    
    # Open in browser
    open _build/html/index.html

Licensing
~~~~~~~~~

By contributing, you agree that your contributions are licensed under the project's license.

Code of Conduct
~~~~~~~~~~~~~~

- Be respectful and inclusive
- Welcome differing viewpoints
- Focus on code quality, not personalities
- Report harassment to moderation team

Questions?
~~~~~~~~~~

- Open a discussion on GitHub
- Check documentation first
- Review existing PRs/issues

Thank you for contributing!
