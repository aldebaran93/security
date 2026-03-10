PKS Integration Guide
=====================

Production Key Server Overview
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The PKS is a SOAP web service that:

- Stores and distributes production keys
- Implements strong authentication/authorization
- Provides key lifecycle management
- Maintains audit trails
- Supports WS-Security

WSDL Configuration
~~~~~~~~~~~~~~~~~~

**Obtaining the WSDL:**

1. Contact PKS administrator for WSDL URL or file
2. URL format: ``https://pks.example.com/KeyService?wsdl``
3. Alternative: Download WSDL file locally

**Loading WSDL:**

In PSMS, go to **Tools** → **PKS Configuration**:

- **WSDL URL**: Enter endpoint or path to WSDL file
- **Client Certificate**: Browse to client certificate (PEM)
- **Private Key**: Browse to private key (PEM)
- **CA Certificate**: Browse to CA cert for server verification

Certificate Setup
~~~~~~~~~~~~~~~~~

**Required Certificates:**

1. **Client Certificate**
   
   - Identifies your PSMS client
   - Issued by PKS administrator
   - Format: PEM or DER

2. **Private Key**
   
   - Protects client certificate
   - Never shared
   - Keep secure (file permissions: 0600)

3. **Server CA Certificate** (optional)
   
   - Verifies PKS server identity
   - Provides trust chain
   - Skip if using public CA

**Certificate Generation (Development):**

.. code-block:: bash

    # Generate private key
    openssl genrsa -out client.key 2048
    
    # Generate certificate signing request
    openssl req -new -key client.key -out client.csr
    
    # Self-signed cert (development only)
    openssl x509 -req -days 365 -in client.csr \
        -signkey client.key -out client.crt

**Certificate Format Conversion:**

.. code-block:: bash

    # DER to PEM
    openssl x509 -inform DER -in cert.der -out cert.pem
    
    # PEM to DER
    openssl x509 -outform DER -in cert.pem -out cert.der

WS-Security Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~

The PSMS implements WS-Security with:

- **Signature**: XML signatures over SOAP body
- **Mutual TLS**: Client and server certificates
- **Timestamp**: Security validity window

Configuration in code:

.. code-block:: python

    pks = ProductionKeyServerClient(
        wsdl_url="https://pks.example.com/KeyService?wsdl",
        client_cert_path="/path/to/client.crt",
        client_key_path="/path/to/client.key",
        ca_cert_path="/path/to/ca.crt"
    )

Key Request Workflow
~~~~~~~~~~~~~~~~~~~~

**Step 1: Prepare Request**

.. code-block:: python

    # User enters VIN in GUI
    vin = "WVWZZZ3CZ9E123456"
    ecu_type = "EngineControl"
    ecu_serial = "SN-20240115120000"

**Step 2: Send SOAP Request**

.. code-block:: python

    keys = pks.request_ecu_keys(
        vin=vin,
        ecu_type=ecu_type,
        ecu_serial=ecu_serial
    )

**Step 3: SOAP Message Structure**

.. code-block:: xml

    <soap:Envelope>
        <soap:Header>
            <wsse:Security>
                <wsse:BinarySecurityToken>...</wsse:BinarySecurityToken>
                <ds:Signature>...</ds:Signature>
            </wsse:Security>
        </soap:Header>
        <soap:Body>
            <RequestECUKeys>
                <VIN>WVWZZZ3CZ9E123456</VIN>
                <ECUType>EngineControl</ECUType>
                <ECUSerial>SN-20240115120000</ECUSerial>
            </RequestECUKeys>
        </soap:Body>
    </soap:Envelope>

**Step 4: Process Response**

Server returns:

.. code-block:: json

    {
        "encryption_key": "base64-encoded-key",
        "authentication_key": "base64-encoded-key",
        "certificate": "base64-encoded-cert",
        "key_id": "KEY-20240115-001",
        "expiry": "2025-01-15T00:00:00Z"
    }

Reporting Injection Status
~~~~~~~~~~~~~~~~~~~~~~~~~~

After key injection completes, report back to PKS:

.. code-block:: python

    success = pks.report_key_injection(
        vin=vin,
        ecu_serial=ecu_serial,
        key_id="KEY-20240115-001",
        status="success"
    )

**Status Values:**

- ``success`` - Key injection completed successfully
- ``failed`` - Key injection failed
- ``pending`` - Still in progress
- ``revoked`` - Key revocation request

PKS API Reference
~~~~~~~~~~~~~~~~~

**RequestECUKeys**

Request vehicle-specific keys from PKS.

.. code-block:: python

    keys = pks.request_ecu_keys(
        vin: str,           # Vehicle Identification Number
        ecu_type: str,      # ECU type (e.g., "EngineControl")
        ecu_serial: str     # ECU serial number
    ) -> Dict[str, Any]

**Returns:**

- ``encryption_key`` - AES key (base64)
- ``authentication_key`` - HMAC key (base64)
- ``certificate`` - X.509 certificate (base64)
- ``key_id`` - Unique key identifier
- ``expiry`` - Key expiration date (ISO 8601)

**ReportKeyInjection**

Report key injection completion to PKS.

.. code-block:: python

    success = pks.report_key_injection(
        vin: str,           # Vehicle ID
        ecu_serial: str,    # ECU serial
        key_id: str,        # Key ID from RequestECUKeys
        status: str         # "success", "failed", etc.
    ) -> bool

Troubleshooting PKS Connection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Issue: "SSL verification failed"**

.. code-block:: python

    # Temporarily disable (development only)
    session.verify = False  # RISKY!
    
    # Or provide CA certificate
    session.verify = "/path/to/ca.pem"

**Issue: "Certificate not trusted"**

1. Verify certificate is valid:
   
   .. code-block:: bash
   
       openssl x509 -text -noout -in client.crt

2. Check certificate expiration

3. Verify client cert is signed by PKS

**Issue: "WSDL parsing error"**

1. Test WSDL accessibility:
   
   .. code-block:: bash
   
       curl -I https://pks.example.com/KeyService?wsdl

2. Verify WSDL format is valid

3. Check for proxy/firewall blocking

**Issue: "Key request rejected"**

1. Verify VIN exists in PKS
2. Check authorization level
3. Ensure ECU is compatible
4. Review PKS audit logs

Security Considerations
~~~~~~~~~~~~~~~~~~~~~~

1. **Certificate Management:**
   
   - Rotate certificates annually
   - Monitor expiration dates
   - Maintain certificate revocation list

2. **TLS Configuration:**
   
   - Use TLS 1.2+ minimum
   - Verify server certificate always
   - Keep Python/OpenSSL updated

3. **Credential Storage:**
   
   - Never hardcode credentials
   - Use environment variables
   - Restrict file permissions (600)

4. **Audit Trail:**
   
   - Log all PKS interactions
   - Track key distribution
   - Monitor for anomalies

See :doc:`architecture` for security model details.
