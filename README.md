# SpringSecuritySampleSetup

## Utils

```bash
#!/bin/bash

# This generates secret used to sign JWT
openssl rand -base64 172 | tr -d '\n'

# This converts an RSA key to a PKCS8 key to encode and decode JWT
openssl pkcs8 -topk8 -in key.private -nocrypt -out pkcs8.key.private
```