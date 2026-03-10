Advanced Configuration
======================

Production Environment Setup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This guide covers advanced setup for production deployments.

Hardware Security Module (HSM) Production Setup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Multi-User HSM Configuration:**

.. code-block:: bash

    # Create multiple PINs for different roles
    softhsm2-util --init-token --slot 0 \
        --label "Production_Primary" \
        --pin 1234567890ABC \
        --so-pin 0987654321XYZ

**Key Backup and Recovery:**

.. code-block:: bash

    # Export public keys for recovery
    pkcs11-tool --list-objects --pin 1234
    pkcs11-tool --read-object --type pubkey --id 01

**Performance Tuning:**

.. code-block:: python

    # Reuse PKCS11 session for multiple operations
    hsm.connect()
    
    # Perform multiple operations
    for i in range(100):
        signature = hsm.sign_data(f'key_{i}', firmware_data)
    
    # Close when done
    hsm.disconnect()

Multi-ECU Vehicle Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Ordering File for Complex Vehicle:**

.. code-block:: json

    {
      "vin": "WVWZZZ3CZ9E234567",
      "model": "ID.7",
      "production_date": "2024-03-10T14:30:00",
      "ecus": [
        {
          "type": "EngineControl",
          "part_number": "0ZS100001",
          "hw_version": "2.0",
          "sw_version": "2.5.0",
          "security_level": 3,
          "requires_secure_boot": true,
          "requires_key_injection": true
        },
        {
          "type": "TransmissionControl",
          "part_number": "0ZS200001",
          "hw_version": "1.5",
          "sw_version": "1.8.2",
          "security_level": 3,
          "requires_secure_boot": true,
          "requires_key_injection": true
        },
        {
          "type": "InfotainmentSystem",
          "part_number": "0ZS300001",
          "hw_version": "3.0",
          "sw_version": "4.2.1",
          "security_level": 2,
          "requires_secure_boot": false,
          "requires_key_injection": true
        },
        {
          "type": "BodyController",
          "part_number": "0ZS400001",
          "hw_version": "1.0",
          "sw_version": "1.1.0",
          "security_level": 1,
          "requires_secure_boot": false,
          "requires_key_injection": false
        }
      ],
      "status": "pending"
    }

**Batch Processing:**

.. code-block:: python

    import json
    
    # Load all ECUs and process in sequence
    order = json.loads(open('complex_order.json').read())
    
    for ecu in order['ecus']:
        if ecu['requires_key_injection']:
            # Request keys for each ECU
            keys = psms.pks.request_ecu_keys(
                order['vin'],
                ecu['type'],
                f"SN-{ecu['part_number']}"
            )
            # Inject into ECU
            success = psms.inject_keys_for_ecu(ecu, keys)

PKS Integration with Multiple Servers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Fallback PKS Configuration:**

.. code-block:: python

    primary_pks = ProductionKeyServerClient(
        wsdl_url="https://pks1.example.com/KeyService?wsdl",
        client_cert_path="certs/client.pem",
        client_key_path="certs/client.key"
    )
    
    backup_pks = ProductionKeyServerClient(
        wsdl_url="https://pks2.example.com/KeyService?wsdl",
        client_cert_path="certs/client.pem",
        client_key_path="certs/client.key"
    )
    
    # Try primary, fall back to backup
    try:
        keys = primary_pks.request_ecu_keys(vin, ecu_type, serial)
    except Exception as e:
        print(f"Primary PKS failed: {e}, trying backup")
        keys = backup_pks.request_ecu_keys(vin, ecu_type, serial)

Custom Authentication
~~~~~~~~~~~~~~~~~~~~~

**LDAP Integration Example:**

.. code-block:: python

    import ldap
    
    def validate_operator(username, password):
        """Validate against LDAP directory"""
        ldap_server = "ldap://ldap.example.com"
        conn = ldap.initialize(ldap_server)
        
        try:
            conn.simple_bind_s(f"cn={username},dc=example,dc=com", password)
            return True
        except ldap.INVALID_CREDENTIALS:
            return False

**Role-Based Access Control:**

.. code-block:: python

    ROLES = {
        'admin': ['configure_hsm', 'configure_pks', 'generate_reports'],
        'operator': ['request_keys', 'inject_keys', 'flash_firmware'],
        'auditor': ['view_logs', 'generate_reports']
    }
    
    def check_permission(user, action):
        user_role = get_user_role(user)
        return action in ROLES.get(user_role, [])

Database Integration
~~~~~~~~~~~~~~~~~~~

**SQLite Backend for Production Orders:**

.. code-block:: python

    import sqlite3
    from datetime import datetime
    
    class ProductionDB:
        def __init__(self, db_path):
            self.conn = sqlite3.connect(db_path)
            self.create_tables()
        
        def create_tables(self):
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS vehicles (
                    id INTEGER PRIMARY KEY,
                    vin TEXT UNIQUE,
                    model TEXT,
                    order_date TIMESTAMP,
                    status TEXT
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS ecu_updates (
                    id INTEGER PRIMARY KEY,
                    vehicle_id INTEGER,
                    ecu_type TEXT,
                    firmware_version TEXT,
                    update_date TIMESTAMP,
                    status TEXT,
                    FOREIGN KEY(vehicle_id) REFERENCES vehicles(id)
                )
            """)
            self.conn.commit()
        
        def record_vehicle(self, vin, model):
            self.conn.execute(
                "INSERT INTO vehicles (vin, model, order_date, status) "
                "VALUES (?, ?, ?, ?)",
                (vin, model, datetime.now(), "pending")
            )
            self.conn.commit()

Automated Testing
~~~~~~~~~~~~~~~~

**Test Suite Structure:**

.. code-block:: python

    import unittest
    from unittest.mock import Mock, patch
    
    class TestSecureUpdate(unittest.TestCase):
        def setUp(self):
            self.manager = SecureUpdateManager(mock_hsm)
        
        def test_prepare_image_with_valid_firmware(self):
            """Test firmware image preparation"""
            result = self.manager.prepare_secure_image(
                'test_firmware.bin',
                '1.0.0',
                'EngineControl'
            )
            self.assertIn('signature', result)
            self.assertIn('metadata', result)
        
        def test_verify_image_with_invalid_signature(self):
            """Test image verification with bad signature"""
            invalid_image = {
                'firmware': 'AAAA',
                'signature': 'INVALID',
                'metadata': {}
            }
            result = self.manager.verify_secure_image(invalid_image)
            self.assertFalse(result)

Continuous Integration
~~~~~~~~~~~~~~~~~~~~~~

**GitHub Actions Workflow:**

.. code-block:: yaml

    name: Security Tests
    
    on: [push, pull_request]
    
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v2
          - name: Install dependencies
            run: pip install -r requirements.txt pytest
          - name: Run tests
            run: pytest tests/
          - name: Security scan
            run: bandit -r pcks_pks_kms.py

Docker Deployment
~~~~~~~~~~~~~~~~

**Dockerfile:**

.. code-block:: dockerfile

    FROM python:3.10-slim
    
    WORKDIR /app
    COPY requirements.txt .
    RUN pip install -r requirements.txt
    
    COPY . .
    
    EXPOSE 5000
    CMD ["python", "pcks_pks_kms.py"]

**Docker Compose:**

.. code-block:: yaml

    version: '3'
    services:
      psms:
        build: .
        ports:
          - "5000:5000"
        environment:
          - HSM_PIN=${HSM_PIN}
          - PKCS11_LIB=${PKCS11_LIB}
        volumes:
          - ./logs:/app/logs
          - ./certs:/app/certs:ro

Monitoring and Alerting
~~~~~~~~~~~~~~~~~~~~~~~

**Key Metrics to Track:**

- Total vehicles processed
- Key request success rate
- Firmware flash failures
- Average processing time per vehicle
- HSM uptime/availability
- PKS response times
- Audit log size

**Example Metrics Collection:**

.. code-block:: python

    class MetricsCollector:
        def __init__(self):
            self.vehicles_processed = 0
            self.keys_requested = 0
            self.keys_failed = 0
            self.total_time = 0
        
        def record_vehicle(self, time_taken):
            self.vehicles_processed += 1
            self.total_time += time_taken
        
        def get_average_time(self):
            return self.total_time / self.vehicles_processed if self.vehicles_processed > 0 else 0
        
        def get_success_rate(self):
            total = self.keys_requested
            if total == 0:
                return 100
            return 100 * (self.keys_requested - self.keys_failed) / total

See related guides: :doc:`architecture`, :doc:`hsm_setup`, :doc:`pks_integration`
