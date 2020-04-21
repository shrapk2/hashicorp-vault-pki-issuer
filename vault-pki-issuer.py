#!/usr/bin/env python3
import argparse
import requests
import json
import urllib3
import os

# ##############################################
# ### SITE SPECIFIC VARS - UPDATE FOR SITE!!!###
# ##############################################
vault_url = "https://vault.example.net"

# test this was created 4/20
vault_svc_id = "sample-service-id"
vault_svc_secret = "sample-service-secret"

issuing_ca = "pki_example-issuingCA"
ca_issuing_role = "webservers-v1"
cert_ttl = "2160h"
# ##############################################
# ##############################################
# ##############################################

# Lazy SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# TODO: Add combo boolean so I'm not generating it every time unless it's needed
# Starting point of script


def read_command_args():
    parser = argparse.ArgumentParser(
        description='Generates client certificates against HashiCorp Vault-based PKI')
    parser.add_argument('--cn', action='store',
                        help='Common Name of requesting certificate'),
    parser.add_argument('--ttl', action='store', default=cert_ttl,
                        help='Certificate expiration TTL -> Default: ' + cert_ttl)
    parser.add_argument('--san', action='store', default="not defined",
                        help='[Optional] Certificate SANs [comma separated if multiple')
    parser.add_argument('--ipsan', action='store', default="not defined",
                        help='[Optional] Certificate IP SANs [comma separated if multiple] ')
    parser.add_argument('--cert_path', action='store', default="/etc/pki/tls/certs",
                        help='Certificate PEM File Path')
    parser.add_argument('--key_path', action='store', default="/etc/pki/tls/private",
                        help='Certificate Key File Path')
    parser.add_argument('--combo_path', action='store', default="/etc/pki/tls/private",
                        help='Certificate PEM/Key Combo File Path')
    parser.add_argument('--chain_path', action='store', default="/etc/pki/tls/certs",
                        help='Certificate CA Chain File Path')
    parser.add_argument('--url', action='store', default=vault_url,
                        help='Vault server URL -> Default: ' + vault_url)
    parser.add_argument('--svcid', action='store', default=vault_svc_id,
                        help='Vault Service ID')
    parser.add_argument('--secret', action='store', default=vault_svc_secret,
                        help='Vault Service ID Secret')
    parser.add_argument('--issuing_ca', action='store', default=issuing_ca,
                        help='Issuing CA Name -> Default: ' + issuing_ca)
    parser.add_argument('--issuing_role', action='store', default=ca_issuing_role,
                        help='Issuing role that provide certificates -> Default: ' + ca_issuing_role)
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Enable debugging. Writes output to console and .results file')
    parser.add_argument('--version', '-v', action='version',
                        version='%(prog)s 1.0')
    args = parser.parse_args()

    if args.cn:
        if args.debug:
            print("Debugging enabled.")
            print()
            print("Using these values:")
            print("    Vault URL:              " + args.url)
            print("    Vault Issuing CA:       " + args.issuing_ca)
            print("    Vault Issuing Role:     " + args.issuing_role)
            print("    Vault Service ID:       " + args.svcid)
            print("    Vault Service Secret:   " + args.secret)
            print()
            print("    Certificate CN:         " + args.cn)
            print("    Certificate TTL:        " + args.ttl)
            print("    Certificate SAN:        " + args.san)
            print("    Certificate IP SAN:     " + args.ipsan)
            print("Paths:")
            print("    Certificate PEM:        " +
                  args.cert_path + args.cn + ".pem")
            print("    Certificate Key:        " +
                  args.key_path + args.cn + ".key")
            print("    Certificate Combo:      " +
                  args.combo_path + args.cn + "-combo.pem")
            print("    Certificate CA Chain:   " +
                  args.chain_path + args.cn + "-chain.pem")
            print()

            vault_pki_api_call(args.debug, args.url, args.issuing_ca, args.issuing_role,
                               args.svcid, args.secret, args.cn, args.ttl, args.san, args.ipsan, args.cert_path, args.key_path, args.combo_path, args.chain_path)
        else:
            vault_pki_api_call(args.debug, args.url, args.issuing_ca, args.issuing_role,
                               args.svcid, args.secret, args.cn, args.ttl, args.san, args.ipsan, args.cert_path, args.key_path, args.combo_path, args.chain_path)
    else:
        print("Use '-h' or '--help' for usage.")
        print()
        print("At a minimum, this command requires the 'common name' (--cn) argument. Also, ensure the defaults below are correct for the environment.")
        print("Current Defaults:")
        print("    Vault URL:              " + args.url)
        print("    Vault Issuing CA:       " + args.issuing_ca)
        print("    Vault Issuing Role:     " + args.issuing_role)
        print("    Vault Service ID:       " + args.svcid)
        print("    Vault Service Secret:   " + args.secret)
        print()
        print("    Certificate CN:         " + "<REQUIRED>")
        print("    Certificate TTL:        " + args.ttl)
        print("    Certificate SAN:        " + args.san)
        print("    Certificate IP SAN:     " + args.ipsan)
        print("Paths:")
        print("    Certificate PEM:        " +
              args.cert_path + "/<cn_value>.pem")
        print("    Certificate Key:        " +
              args.key_path + "/<cn_value>.key")
        print("    Certificate Combo:      " +
              args.combo_path + "/<cn_value>-combo.pem")
        print("    Certificate CA Chain:   " +
              args.chain_path + "/<cn_value>-chain.pem")
        print()


def vault_pki_api_call(debug, url, issuing_ca, issuing_role, svcid, secret, cn, ttl, san, ipsan, cert_path, key_path, combo_path, chain_path):

    # Get Vault Token
    tokenreq_url = url + "/v1/auth/approle/login"
    tokenreq_params = ""
    tokenreq_payload = {"role_id": f"{svcid}", "secret_id": f"{secret}"}

    token_request = requests.post(
        # Shouldn't verify=False
        tokenreq_url, data=json.dumps(tokenreq_payload), verify=False
    )

    tokenreq_json = token_request.json()

    auth_token = tokenreq_json["auth"]["client_token"]

    if debug:
        print(f"Authentication token: {auth_token}")
    else:
        pass

    # Request Certificate
    certreq_url = url + "/v1/" + issuing_ca + "/issue/" + issuing_role
    certreq_header = {"X-Vault-Token": f"{auth_token}"}
    if "not defined" in san:
        if "not defined" in ipsan:
            certreq_payload = {"common_name": f"{cn}", "ttl": f"{ttl}"}
        else:
            certreq_payload = {"common_name": f"{cn}", "ttl": f"{ttl}",
                               "ip_sans": f"{ipsan}"}
    else:
        if "not defined" in ipsan:
            certreq_payload = {"common_name": f"{cn}", "ttl": f"{ttl}",
                               "alt_names": f"{san}"}
        else:
            certreq_payload = {"common_name": f"{cn}", "ttl": f"{ttl}",
                               "alt_names": f"{san}", "ip_sans": f"{ipsan}"}

    cert_request = requests.post(
        # Shouldn't verify=False
        certreq_url, headers=certreq_header, data=json.dumps(certreq_payload), verify=False
    )

    certreq_json = cert_request.json()
    certreq_json_tidy = json.dumps(certreq_json, indent=4)

    certreq_cert = certreq_json["data"]["certificate"]
    certreq_key = certreq_json["data"]["private_key"]
    certreq_combo = certreq_json["data"]["private_key"] + "\n" + \
        certreq_json["data"]["certificate"]
    certreq_chain = certreq_json["data"]["ca_chain"][0]

    if debug:
        certreq_results_file = open(cert_path + cn + ".results", "w")
        certreq_results_file.write(certreq_json_tidy)
        certreq_results_file.close
        print(certreq_json_tidy)
        print(certreq_cert)
        print(certreq_key)
        print(certreq_combo)
        print(certreq_chain)
    else:
        pass

    # Write certificate data to files
    certfile_cert = open(cert_path + "/" + cn + ".pem", "w")
    certfile_key = open(cert_path + "/" + cn + ".key", "w")
    certfile_combo = open(cert_path + "/" + cn + "-combo.pem", "w")
    certfile_chain = open(cert_path + "/" + cn + "-chain.pem", "w")

    certfile_cert.write(certreq_cert)
    certfile_key.write(certreq_key)
    certfile_combo.write(certreq_combo)
    certfile_chain.write(certreq_chain)

    for file in [certfile_cert, certfile_key, certfile_combo, certfile_chain]:
        file.close()

    # Adjust permissions to key files
    os.chmod(cert_path + cn + ".key", 0o600)
    os.chmod(cert_path + cn + "-combo.key", 0o600)


# Starts the party
if __name__ == '__main__':
    read_command_args()
