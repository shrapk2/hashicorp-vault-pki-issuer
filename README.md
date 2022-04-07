# vault-pki-issuer

Python script to issue certificates from a HashiCorp Vault-based Public Key Infrastructure.

## Prerequisites

Using this script assumes you have the following in place:

1. HashiCorp Vault implementation and HTTPS accessible
2. Correct PKI implementation and restricted RBAC See: [Publication_Pending](https://not_posted_yet)
3. Service account with proper permissions restrictions to only issue certificates
4. Python3 installed on the executing system

### Python Dependencies

- pyopenssl
- argparse
- requests
- json
- urllib3
- os
- socket
- ssl
- datetime

## Installing

Simply `git clone` the Python executable and go crazy. Or just download the `vault-pki-issuer.py` script, no clone required.

## Examples

Below are some examples as to how to execute the script with various environment variables:

```bash
python3 /path/to/vault-pki-issuer.py --cn "mywebsite.example.net" --debug
```

```bash
python3 /path/to/vault-pki-issuer.py --help
usage: vault-pki-issuer.py [-h] [--cn CN] [--ttl TTL] [--san SAN]
                           [--ipsan IPSAN] [--cert_path CERT_PATH]
                           [--key_path KEY_PATH] [--combo_path COMBO_PATH]
                           [--chain_path CHAIN_PATH] [--url URL]
                           [--svcid SVCID] [--secret SECRET]
                           [--issuing_ca ISSUING_CA]
                           [--issuing_role ISSUING_ROLE] [--debug] [--combo]
                           [--force] [--version]

Generates client certificates against HashiCorp Vault-based PKI

optional arguments:
  -h, --help            show this help message and exit
  --cn CN               Common Name of requesting certificate
  --ttl TTL             Certificate expiration TTL -> Default: 2160h
  --san SAN             [Optional] Certificate SANs [comma separated if
                        multiple
  --ipsan IPSAN         [Optional] Certificate IP SANs [comma separated if
                        multiple]
  --cert_path CERT_PATH
                        Certificate PEM File Path
  --key_path KEY_PATH   Certificate Key File Path
  --combo_path COMBO_PATH
                        Certificate PEM/Key Combo File Path
  --chain_path CHAIN_PATH
                        Certificate CA Chain File Path
  --url URL             Vault server URL -> Default: https://vault.example.net
  --svcid SVCID         Vault Service ID
  --secret SECRET       Vault Service ID Secret
  --issuing_ca ISSUING_CA
                        Issuing CA Name -> Default: pki_example-issuingCA
  --issuing_role ISSUING_ROLE
                        Issuing role that provide certificates -> Default:
                        webservers-v1
  --debug, -d           Enable debugging. Writes output to console and
                        .results file
  --combo               Simply generate the <cn_value>-combo.pem certificate.
                        No other certificates will be created.
  --force, -f           Skip certificate validation and directly issue the
                        certificate.
  --version, -v         show program's version number and exit

## Current defaults without arguments:
Current Defaults:
    Vault URL:              https://vault.example.net
    Vault Issuing CA:       pki_example-issuingCA
    Vault Issuing Role:     webservers-v1
    Vault Service ID:       sample-service-id
    Vault Service Secret:   sample-service-secret

    Certificate CN:         <REQUIRED>
    Certificate TTL:        2160h
    Certificate SAN:        not defined
    Certificate IP SAN:     not defined
Paths:
    Certificate PEM:        /etc/pki/tls/certs/<cn_value>.pem
    Certificate Key:        /etc/pki/tls/private/<cn_value>.key
    Certificate Combo:      /etc/pki/tls/private/<cn_value>-combo.pem
    Certificate CA Chain:   /etc/pki/tls/certs/<cn_value>-chain.pem
```

## Built With

- Python

## Authors

- shrapk2

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

- OSS projects providing examples and ideas
- [Google Search](https://www.google.com)
- Linux Academy
