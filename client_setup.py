#!/usr/bin/env python

"""
A module which simplifies the process of preparing client(s) to use the
gdp discovery service. A call to setup_client or its command line
equivalent will create private key for the number of clients desired and
write the client(s) information to an info_log.

Before using client_setup, an info_log and its signing key file must already
exist. Additionally, a configuration file must be provided which describes
the client(s) capabilities and permissions in the following format:

### Usage ###

Example:
> capabilities = ['temperature', 'motion']
> permissions = ['paying_customers', 'free']
> discovery.client_setup.setup_client(info_log, info_log_key, capabilities,
                   permissions, num_clients=4, ca_key='CA.key', ca_crt='CA.pem')


Alternatively, setup can be called using the command line as specified in main().
If the command line interface is used, a configuration file must be provided
which describes the client(s) capabilities and permissions in the following
format:

CAPABILITIES:
<capability 1>
<capability 2>
...
<capability n>
PERMISSIONS:
<permission 1>
<permission 2>
...
<permission n>
"""

import sys
sys.path.append("../") # So that we can actually load the python_api module
import gdp
import hashlib
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from optparse import OptionParser

def setup_client(info_log, signing_key_file, capabilities, permissions, insecure=False,
                 router=None, num_clients=1, ca_key=None, ca_crt=None):
    """
    Performs the following:
    - Creates num_clients number of private keys for clients and writes them
      to the current directory
    - Writes capabilities and permissions to the info_log
    - Writes a public key for each client to the info_log
    - Writes a certificate signed by a CA to the info_log if a CA key and CA
      certificate is provided

    Parameters:
    info_log - 43 byte name of the empty log to which the client(s) information
               will be written
    signing_key_file - signing key file in pem format for the info_log
    capabilities - list of capabilities of the client(s)
    permissions - list of the permissions of the clinet(s)
    insecure - if False, key pairs for each client will be produced and gdp discovery
               services will perform authentication wit hthe client(s). Otherwise
               they will be authenticated.
    router - address and port of gdp router in "<address>:<port>" format
    num_clients - number of key pairs to be produced
    ca_key and ca_crt - used to sign the info_log's certificate. If these are not
                        provided, the info_log will not be certified.
    """
    # Initialize GDP
    if router:
        router = router.split(":")
        host = router[0]
        port = int(router[1])
        gdp.gdp_init(host, port)
    else:
        gdp.gdp_init()

    # Open the info_log
    info_log_name = info_log
    skey = gdp.EP_CRYPTO_KEY(filename=signing_key_file,
                             keyform=gdp.EP_CRYPTO_KEYFORM_PEM,
                             flags=gdp.EP_CRYPTO_F_SECRET)
    gcl_name = gdp.GDP_NAME(info_log_name)
    gcl_handle = gdp.GDP_GCL(gcl_name, gdp.GDP_MODE_AO,
                             open_info={'skey':skey})

    # Write capabilities and permissions to info_log

    datum = {"data": str(len(capabilities))}
    gcl_handle.append(datum) # Write number of capabilities
    datum = {"data": str(len(permissions))}
    gcl_handle.append(datum) # Write number of permissions
    datum = {"data": str(num_clients)}
    gcl_handle.append(datum) # Write number of public keys
    for capability in capabilities: # Write capabilities
        datum = {"data": capability}
        gcl_handle.append(datum)
    for permission in permissions: # Write permissions
        datum = {"data": permission}
        gcl_handle.append(datum)

    # Create key(s)
    if not insecure:
        random_generator = Random.new()
        for i in range(num_clients):
            key = RSA.generate(1024, random_generator.read)
            # Write key to file
            keyfile = open("key" + str(i) + ".pem", 'w')
            keyfile.write(key.exportKey(format='PEM'))
            datum = {"data": key.publickey().exportKey(format='PEM')}
            gcl_handle.append(datum)   

    # Create a certificate and write it to the info log
    if ca_crt and ca_key:
        # load CA cert and key
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(ca_crt).read())
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(ca_key).read())
        
        # create info_log key
        info_log_key = crypto.PKey()
        info_log_key.generate_key(crypto.TYPE_RSA, 2048)

        # create CSR
        req = crypto.X509Req()
        req.get_subject().CN = info_log_name
        req.set_pubkey(info_log_key)
        req.sign(info_log_key, 'sha256')

        # create unique serial number using info_log name
        md5_hash = hashlib.md5()
        md5_hash.update(info_log_name)
        serial = int(md5_hash.hexdigest(), 36)

        # create certificate
        cert = crypto.X509()
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*4*60*60*1000) # make certificate last 1000 yrs
        cert.set_issuer(ca_cert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(ca_key, 'sha256')

        # write certificate to info_log
        datum = {"data": crypto.dump_certificate(crypto.FILETYPE_PEM, cert)}
        gcl_handle.append(datum)
   

def main():
    """
    Command line wrapper for a call to setup_client.

    Writes information in a registration configuration file to an empty info log and
    creates a public/private key pair for the client.
    """ 
    usage = "usage: %prog [options] <info_log> <info_log signing-key-file> " + \
            "<registration_config-file>"   
    parser = OptionParser(usage)
    parser.add_option("-i", "--insecure", action="store_true", dest="insecure",
                      default=False, help="do not create a key pair")
    parser.add_option("-r", "--router", dest="router",
                      help="use gdp router specified in the form ip:port")
    parser.add_option("-m", "--multiple", dest="num_clients", default="1",
                      help="specify number of key pairs (clients)")
    parser.add_option("-c", "--certificate", dest="certificate", nargs=2,
                      help="embed a X509 certificate in the info_log. " + \
                           "-c <ca key> <ca cert pem>")
    (options, args) = parser.parse_args()

    # Read capabilities and permissions from registration_config-file
    capabilities = []
    permissions = []
    reading_permissions = False
    with open(args[2]) as f:
        for line in f:
            line = line.strip()
            if line == "CAPABILITIES:":
                pass
            elif line == "PERMISSIONS:":
                reading_permissions = True
            elif not reading_permissions:
                capabilities.append(line)
            else:
                permissions.append(line)

    if options.certificate:
        setup_client(args[0], args[1], capabilities, permissions, options.insecure, 
                     options.router, int(options.num_clients), options.certificate[0], 
                     options.certificate[1])
    else:
        setup_client(args[0], args[1], capabilities, permissions, options.insecure, 
                     options.router, int(options.num_clients))

if __name__ == "__main__":
    main()

