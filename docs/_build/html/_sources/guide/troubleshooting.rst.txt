Troubleshooting Guide
====================

Connection Issues
~~~~~~~~~~~~~~~~~

**Problem: "HSM connection failed"**

**Symptoms:**

- Error message in GUI
- Red status indicator for HSM
- Operations fail with HSM error

**Solution:**

1. Verify PKCS#11 library path:

   .. code-block:: python

       import os
       print(os.path.exists("C:\\Program Files\\SoftHSM2\\lib\\softhsm2.dll"))

2. Check library is correct bit depth (32/64):

   .. code-block:: bash

       file softhsm2.dll  # On Linux

3. Verify HSM is powered on and connected

4. Check PIN is correct (case-sensitive)

5. Reinitialize HSM token:

   .. code-block:: bash

       softhsm2-util --init-token --slot 0 --label "Test"

6. Try alternative slot (0, 1, 2, etc.)

---

**Problem: "Slot not found"**

**Solution:**

1. List available slots:

   .. code-block:: bash

       softhsm2-util --show-slots

2. Verify slot number matches configuration

3. Ensure HSM is connected before PSMS startup

4. Update PKCS#11 driver if available

---

**Problem: "Token not initialized"**

**Solution:**

.. code-block:: bash

    # Reinitialize token
    softhsm2-util --init-token --slot 0 \
        --label "MyToken" \
        --pin 1234 \
        --so-pin 1234

---

**Problem: PIN verification failed**

**Symptoms:**

- "CKR_PIN_INCORRECT" error
- Cannot authenticate to HSM

**Solution:**

1. Verify correct PIN is entered
2. Check PIN is not locked (too many failed attempts):

   .. code-block:: bash

       softhsm2-util --show-slots

3. Reset token if locked:

   .. code-block:: bash

       softhsm2-util --delete-token --token MyToken

4. Reinitialize with correct PIN

PKS Connection Issues
~~~~~~~~~~~~~~~~~~~~

**Problem: "WSDL parsing error"**

**Symptoms:**

- SOAP client initialization fails
- XML parsing exception

**Solution:**

1. Verify WSDL is accessible:

   .. code-block:: bash

       curl https://pks.example.com/KeyService?wsdl

2. Validate WSDL XML:

   .. code-block:: bash

       xmllint pks.wsdl

3. Check for firewall/proxy blocking:

   .. code-block:: bash

       ping pks.example.com
       tracert pks.example.com

4. Test with cached WSDL file instead of URL

---

**Problem: "SSL verification failed"**

**Symptoms:**

- "certificate_verify_failed" error
- Connection refused

**Cause:** Certificate validation failure

**Solution:**

1. Verify server certificate:

   .. code-block:: bash

       openssl s_client -connect pks.example.com:443

2. Check certificate expiration:

   .. code-block:: bash

       openssl x509 -noout -dates -in server.crt

3. Verify CA certificate is trusted:

   .. code-block:: bash

       openssl verify -CAfile ca.pem server.crt

4. For testing only, disable verification (NOT PRODUCTION):

   .. code-block:: python

       pks.session.verify = False  # INSECURE!

---

**Problem: "Client certificate rejected"**

**Symptoms:**

- "CertificateError" during connection
- PKS returns 403 Forbidden

**Solution:**

1. Verify client certificate is valid:

   .. code-block:: bash

       openssl x509 -text -noout -in client.crt

2. Check certificate is not expired:

   .. code-block:: bash

       openssl x509 -noout -dates -in client.crt

3. Verify certificate is signed by PKS CA:

   .. code-block:: bash

       openssl verify -CAfile pks-ca.pem client.crt

4. Check private key matches certificate:

   .. code-block:: bash

       openssl pkey -in client.key -pubout > key.pub
       openssl x509 -in client.crt -pubkey -noout > cert.pub
       diff key.pub cert.pub

5. Re-request certificate from PKS administrator

Firmware Update Issues
~~~~~~~~~~~~~~~~~~~~~

**Problem: "Firmware file not found"**

**Solution:**

1. Verify file exists:

   .. code-block:: bash

       ls -la firmware.bin
       dir /l firmware.bin  # Windows

2. Check file permissions (readable):

   .. code-block:: bash

       chmod 644 firmware.bin

3. Verify full path in dialog (not relative path)

---

**Problem: "Image verification failed"**

**Symptoms:**

- Secure image cannot be verified
- Signature validation fails

**Solution:**

1. Verify firmware file is not corrupted:

   .. code-block:: bash

       sha256sum firmware.bin

2. Check signature process:

   .. code-block:: python

       # Verify signature manually
       from cryptography.hazmat.primitives import hashes
       from cryptography.hazmat.primitives.asymmetric import padding
       
       public_key.verify(signature, metadata_bytes, padding.PKCS1v15(), hashes.SHA256())

3. Ensure HSM signing key exists:

   .. code-block:: bash

       pkcs11-tool --list-objects

4. Regenerate image with valid HSM connection

---

**Problem: "ECU signature verification failed"**

**Symptoms:**

- ECU rejects firmware update
- Flash operation fails

**Solution:**

1. Verify ECU has correct public key:

   .. code-block:: bash

       # Ask ECU bootloader for public key hash

2. Check firmware signature algorithm matches ECU expectations

3. Verify timestamp in firmware is recent (not expired)

4. Check ECU bootloader version supports verification

5. Update ECU bootloader if available

Logging and Audit
~~~~~~~~~~~~~~~~

**Problem: "Audit log files growing too large"**

**Solution:**

1. Implement log rotation:

   .. code-block:: python

       from logging.handlers import RotatingFileHandler
       handler = RotatingFileHandler('audit.log', maxBytes=10*1024*1024, backupCount=10)

2. Archive old logs:

   .. code-block:: bash

       gzip audit.log.* && mv *.gz /archive/

3. Implement external logging:

   .. code-block:: python

       import logging.handlers
       syslog_handler = logging.handlers.SysLogHandler(address='syslog.server.com')

---

**Problem: "Cannot export audit log"**

**Solution:**

1. Check write permissions:

   .. code-block:: bash

       ls -la /path/to/export/
       touch /path/to/export/test.txt

2. Verify sufficient disk space:

   .. code-block:: bash

       df -h

3. Check file name for special characters

4. Try exporting to different location

Performance Issues
~~~~~~~~~~~~~~~~~

**Problem: "PSMS running slowly"**

**Diagnosis:**

1. Check CPU usage:

   .. code-block:: bash

       top -p $(pgrep python)  # Linux
       taskmgr  # Windows

2. Monitor memory usage

3. Check network latency:

   .. code-block:: bash

       ping pks.example.com
       time curl https://pks.example.com/KeyService?wsdl

**Solutions:**

- Reduce HSM session creation frequency
- Cache PKS responses
- Use connection pooling for SOAP
- Run PSMS on dedicated machine
- Upgrade network bandwidth

---

**Problem: "Key request takes too long"**

**Solution:**

1. Measure network latency:

   .. code-block:: bash

       ping -c 5 pks.example.com

2. Check PKS server load

3. Verify network connectivity:

   .. code-block:: bash

       mtr pks.example.com

4. Consider request batching

5. Implement caching for frequently requested keys

Database/File Issues
~~~~~~~~~~~~~~~~~~~

**Problem: "Cannot load production order"**

**Symptoms:**

- "JSON parse error"
- File not found

**Solution:**

1. Validate JSON syntax:

   .. code-block:: bash

       python -m json.tool order.json

2. Check file encoding (UTF-8):

   .. code-block:: bash

       file order.json

3. Verify all required fields are present:

   .. code-block:: python

       required = ['vin', 'model', 'ecus']
       for field in required:
           assert field in order

4. Check file permissions

---

**Problem: "Database corruption"**

**Solution:**

1. Restore from backup

2. Verify database integrity:

   .. code-block:: bash

       sqlite3 production.db "PRAGMA integrity_check;"

3. Rebuild database if corrupted

Security Issues
~~~~~~~~~~~~~~

**Problem: "Unauthorized access to HSM"**

**Solution:**

1. Restrict file permissions:

   .. code-block:: bash

       chmod 600 client.key
       chmod 600 hsm.conf

2. Implement access control

3. Enable HSM audit logging

4. Monitor HSM access logs

---

**Problem: "Certificate compromise suspected"**

**Solution:**

1. Revoke compromised certificate immediately

2. Request new certificate from CA

3. Update all PSMS instances

4. Audit all operations since compromise

5. Re-sign all firmware images with new key

Getting Help
~~~~~~~~~~~~

1. **Check Logs First:**

   .. code-block:: bash

       tail -f psms.log
       tail -f audit.log

2. **Test Individual Components:**

   .. code-block:: bash

       # Test HSM
       pkcs11-tool --list-objects
       
       # Test PKS
       curl https://pks.example.com/KeyService?wsdl
       
       # Test Network
       ping pks.example.com

3. **Enable Debug Logging:**

   .. code-block:: python

       logging.basicConfig(level=logging.DEBUG)

4. **Consult Related Guides:**

   - :doc:`hsm_setup`
   - :doc:`pks_integration`
   - :doc:`architecture`

5. **Contact Support:**

   - Check :doc:`faq`
   - Review system logs
   - Describe error exactly as it appears
