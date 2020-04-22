#!/usr/bin/env python3
import argparse
import requests
import json
import urllib3
import os
import socket
import ssl
import datetime
from OpenSSL import crypto

# ##############################################
# ### SITE SPECIFIC VARS - UPDATE FOR SITE!!!###
# ##############################################
vault_url = "https://vault.example.net"
vault_svc_id = "sample-service-id"
vault_svc_secret = "sample-service-secret"

issuing_ca = "pki_example-issuingCA"
ca_issuing_role = "webservers-v1"
cert_ttl = "2160h"

cert_path = "/etc/pki/tls/certs"
key_path = "/etc/pki/tls/private"
combo_path = "/etc/pki/tls/private"
chain_path = "/etc/pki/tls/certs"

# Number of days until you want to initiate a renewal
days_threshold = 14  # 14
service_port = 443
# ##############################################
# ##############################################
# ##############################################

# Lazy SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
    parser.add_argument('--cert_path', action='store', default=cert_path,
                        help='Certificate PEM File Path')
    parser.add_argument('--key_path', action='store', default=key_path,
                        help='Certificate Key File Path')
    parser.add_argument('--combo_path', action='store', default=combo_path,
                        help='Certificate PEM/Key Combo File Path')
    parser.add_argument('--chain_path', action='store', default=chain_path,
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
    parser.add_argument('--combo', action='store_true',
                        help='Simply generate the <cn_value>-combo.pem certificate.  No other certificates will be created.')
    parser.add_argument('--force', '-f', action='store_true',
                        help='Skip certificate validation and directly issue the certificate.')
    parser.add_argument('--version', '-v', action='version',
                        version='%(prog)s 1.1')
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
                  args.cert_path + "/" + args.cn + ".pem")
            print("    Certificate Key:        " +
                  args.key_path + "/" + args.cn + ".key")
            print("    Certificate Combo:      " +
                  args.combo_path + "/" + args.cn + "-combo.pem")
            print("    Certificate CA Chain:   " +
                  args.chain_path + "/" + args.cn + "-chain.pem")
            print()

            if args.force:
                vault_pki_api_call(args.debug, args.url, args.issuing_ca, args.issuing_role,
                                   args.svcid, args.secret, args.cn, args.ttl, args.san, args.ipsan, args.cert_path, args.key_path, args.combo_path, args.chain_path, args.combo)
            else:
                if certificate_validation(args.debug, args.cert_path, args.cn):
                    vault_pki_api_call(args.debug, args.url, args.issuing_ca, args.issuing_role,
                                       args.svcid, args.secret, args.cn, args.ttl, args.san, args.ipsan, args.cert_path, args.key_path, args.combo_path, args.chain_path, args.combo)
                else:
                    print(
                        "Certificate validation failed. Correct issues or use '--force'")
        else:
            if args.force:
                vault_pki_api_call(args.debug, args.url, args.issuing_ca, args.issuing_role,
                                   args.svcid, args.secret, args.cn, args.ttl, args.san, args.ipsan, args.cert_path, args.key_path, args.combo_path, args.chain_path, args.combo)
            else:
                certificate_validation(args.debug, args.cert_path, args.cn)
                vault_pki_api_call(args.debug, args.url, args.issuing_ca, args.issuing_role,
                                   args.svcid, args.secret, args.cn, args.ttl, args.san, args.ipsan, args.cert_path, args.key_path, args.combo_path, args.chain_path, args.combo)
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


def certificate_validation(debug, cert_path, cn):
    if ssl_certificate_validation(debug, cert_path, cn):
        print("We reached it")
        exit()
        return file_certificate_validation(debug, cert_path, cn)
    else:
        return file_certificate_validation(debug, cert_path, cn)


def ssl_certificate_validation(debug, cert_path, cn):
    cert_date_format = r'%b %d %H:%M:%S %Y %Z'
    # hostname = 'kloud.sharpton.us'  # cn
    context = ssl.create_default_context()
    #context.check_hostname = False
    #context.verify_mode = ssl.CERT_OPTIONAL

    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=cn,
    )
    conn.settimeout(3.0)

    try:
        conn.connect((cn, service_port))
    except socket.gaierror:
        if debug:
            print(
                f"SSL connectivity issues.  Check DNS and/or '{cn}:{service_port}' availability.")
            print(
                "SSL Validation failed, attempting file validation.")
            return False
        else:
            print(
                "SSL Validation failed, attempting file validation.  Use '--debug' for more information.")
            return False
    except ssl.SSLCertVerificationError:
        # except ssl.SSLCertVerificationError:
        if debug:
            print(f"Validation failed on {cn}:{service_port}")
            print()
            print(
                f"CA not trusted (likely not in the local root CA store)! \n - Can not validate certificate chain. \n - Not uncommon for custom CAs to be invalid.  \n - Suggest using 'openssl s_client -connect {cn}' to troubleshoot.")
            print(
                "SSL Validation failed, attempting file validation.")
            return False
        else:
            print(
                "SSL Validation failed, attempting file validation.  Use '--debug' for more information.")
            return False
    else:
        ssl_info = conn.getpeercert()
        # print(ssl_info['notAfter'])
        ssl_expiry_time = datetime.datetime.strptime(
            ssl_info['notAfter'], cert_date_format)

        if debug:
            print(f"Certificate expiry time: {ssl_expiry_time.isoformat()}")
            return expiry_validation(ssl_expiry_time)
        else:
            return expiry_validation(ssl_expiry_time)


def file_certificate_validation(debug, cert_path, cn):
    cert_file = cert_path + "/" + cn + ".pem"

    if os.path.isfile(cert_file):
        cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, open(cert_file).read())
        subject = cert.get_subject()
        issued_to = subject.CN    # the Common Name field
        issuer = cert.get_issuer()
        not_after = cert.get_notAfter()

        parsed_time = datetime.datetime.strptime(
            not_after.decode('ascii'), '%Y%m%d%H%M%SZ')

        if debug:
            print("PEM Certificate File Validation")
            print(f"Using the following path: {cert_path}/")
            print(issued_to)
            print(not_after)
            print(parsed_time.isoformat())
            return expiry_validation(parsed_time)

        else:
            return expiry_validation(parsed_time)
    else:
        print("File not found, certificate request will not be attempted. Use '--debug' for more information.")
        print("To ignore errors and continue with certificate request, use '--force'.")
        exit()


def time_remaining(expiry_time):
    expires = expiry_time
    return expires - datetime.datetime.utcnow()


def expiry_validation(expiry_time):
    time_check = time_remaining(expiry_time)

    if time_check < datetime.timedelta(days=days_threshold):
        print(f"Expires within 14 days, renewing.")
        return True
    else:
        print("Certificate valid for %s days.  No need to renew." %
              time_check.days)
        exit()


def vault_pki_api_call(debug, url, issuing_ca, issuing_role, svcid, secret, cn, ttl, san, ipsan, cert_path, key_path, combo_path, chain_path, combo):

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
    if combo:
        certfile_combo = open(cert_path + "/" + cn + "-combo.pem", "w")
        certfile_combo.write(certreq_combo)
        certfile_combo.close()
        os.chmod(cert_path + "/" + cn + "-combo.pem", 0o600)
        exit()
    else:
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
        os.chmod(cert_path + "/" + cn + ".key", 0o600)
        os.chmod(cert_path + "/" + cn + "-combo.pem", 0o600)


# Starts the party
if __name__ == '__main__':
    read_command_args()
