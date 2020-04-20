# vault-pki-issuer

Python script to issue certificates from a HashiCorp Vault-based Public Key Infrastructure.

### Prerequisites

Using this script assumes you have the following in place:

1. HashiCorp Vault implementation and HTTPS accessible
2. Correct PKI implementation and restricted RBAC (See: [Publication_Pending](Vault PKI Configuration Shell Scripts))
3. Service account with proper permissions restrictions to only issue certificates
4. Python3 installed on the executing system

### Installing

Simply `git clone` the Python executable and go crazy

## Examples

Below are some examples as to how to execute the script with various environment variables:

```bash
python3 /path/to/script.py --name --data1
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
