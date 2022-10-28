
============================================================================
OBSOLETE: PLEASE USE https://github.com/foundriesio/pkcs11-cert-import-apdu
============================================================================


Import NXPSE050 Secure Objects to PKCS
=======================================

Intro and Usage
----------------

This Secured Utility allows the user to import pre-provised keys and certificates from the NXP SE050 via OP-TEE into the pkcs11 database.

Examples of usage::

  
  * RSA-2048 key with the NXP SE050 id 0xf0000110
    pkcs11-se050-import --keyp 0xf0000110 --id 87 --pin 87654321 --token-label aktualizr --key-type RSA:2048
    
  * NXP SE050 Certficate with the id 0xf0000123
    pkcs11-se050-import --cert 0xf0000123 --id 45 --pin 87654321


Building the Secured Utility
----------------------------

From the root directory do as follows::

    export CROSS_COMPILE=aarch64-linux-gnu-
    export TEEC_EXPORT=/path/to/optee-client/out/libteec
    export CFLAGS="-I/path/to/optee-client/libteec/include/linux/ -I/path/to/optee-client/public/"
    make


Have fun::

            _  _
           | \/ |
        \__|____|__/   
          |  o  o|           Thumbs Up
          |___\/_|_____||_
          |       _____|__|
          |      |
          |______|
          | |  | |
          | |  | |
          |_|  |_|


Foundries.io
