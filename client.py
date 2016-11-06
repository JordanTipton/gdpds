#!/usr/bin/env python

"""
A module which can be run on a client device or gateway which advertises
itself to the gdp discovery service on a local subnet using Avahi Zeroconf.

Any gdp-discovery zeroconf service on the client's network will be sent an
gdp discovery RPC connection message registering the client with the 
discovery service. Renewal RPC messages will then be periodically sent to
the server until advertise is interrupted.

### Usage ###

> advertise(client_guid, info_log_name, output_log_name, input_log_name,
            gdp_router='192.168.453.234:8007', key_file='key0.pem')

Public interface:
* Advertise:
  Sends RPC connection and renewal RPC messages to discovery services on 
  the local network.
"""

import sys
sys.path.append("../")
import gdp
import time
import argparse
import dbus
import gobject
import avahi
import socket
from dbus import DBusException
from dbus.mainloop.glib import DBusGMainLoop
from struct import pack, unpack
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5

#Zeroconf variables
TYPE = '_gdp-discovery._tcp'
loop = DBusGMainLoop()
bus = dbus.SystemBus(mainloop=loop)

server = dbus.Interface( bus.get_object(avahi.DBUS_NAME, '/'),
    'org.freedesktop.Avahi.Server') #TODO: change this

sbrowser = dbus.Interface(bus.get_object(avahi.DBUS_NAME,
    server.ServiceBrowserNew(avahi.IF_UNSPEC,
        avahi.PROTO_UNSPEC, TYPE, 'local', dbus.UInt32(0))),
    avahi.DBUS_INTERFACE_SERVICE_BROWSER)

#Client info variables
client_guid = None
client_info_log = None
client_input_log = None
client_output_log = None
key = None

#Other constants
RENEWAL_TIME = 25 # Time to wait before sending renewal messages to discover server

def conn_msg():
    """
    Generates a 'discconn' RPC message
    """
    RPC_name_len = pack('!B', 8)
    RPC_type = pack('!B', 0)
    RPC_req_name = pack('!8s', "discconn")
    guid = pack('!32s', client_guid)
    info_log = pack('!43s', client_info_log)
    input_log = ""
    output_log = ""
    if key:
        public_key = key.publickey().exportKey() 
        has_key = True
    else:
        public_key = ""
        has_key = False
    if client_input_log and not client_output_log:
        if has_key:
            conn_type = pack('!B', 0x80)
        else:
            conn_type = pack('!B', 0x00)
        input_log = pack('!43s', client_input_log)
    elif not client_input_log and client_output_log:
        if has_key:
            conn_type = pack('!B', 0x81)
        else:
            conn_type = pack('!B', 0x01)
        output_log = pack('!43s', client_output_log)
    elif client_input_log and client_output_log:
        if has_key:
            conn_type = pack('!B', 0x82)
        else:
            conn_type = pack('!B', 0x02)
        input_log = pack('!43s', client_input_log)
        output_log = pack('!43s', client_output_log)
    else:
        raise Exception('Invalid connection type')

    msg_1 = RPC_name_len + RPC_type
    msg_2 = RPC_req_name + conn_type + guid + info_log + \
            input_log + output_log + public_key
    payload_len = len(msg_2)
    msg = msg_1 + pack('!i', payload_len) + msg_2
    return msg


def check_ack(msg):
    """
    Returns True if msg is a valid success ack otherwise returns False
    """
    rpc_name_len, = unpack('!B', msg[0])
    rpc_type, = unpack('!B', msg[1])
    data_len, = unpack('!i', msg[2:6])
    if rpc_type != 1:
        return False
    return True

def is_ip(addr):
    """
    Returns True if addr is an IP address. Otherwise returns False
    """
    is_num = lambda x: ord(x) > 47 and ord(x) < 58

    if len(addr) > 15 or not is_num(addr[0]) or not is_num(addr[-1]):
        # Can't be too long or have a non-number at start or finish
        return False
    i = 0
    num_dot = 0
    num_num = 0
    while i < len(addr):
        if addr[i] == "." and addr[i - 1] == ".":
            #Can't have two periods in a row
            return False
        if addr[i] == ".":
            if addr[i - 1] == ".":
                # Can't have two periods in a row
                return False
            num_dot += 1
            num_num = 0
            i += 1
        elif is_num(addr[i]):
            if num_num > 2:
                # Can't have more than 3 in a row
                return False
            num_num += 1
            i += 1
        else:
            # Not a number
            return False

    if num_dot == 3:
        return True
    else:
        return False

def send_renewals(server_addr):
   """
   Send renewal message to discovery service at server_addr every RENEWAL_TIME seconds
   """
   RPC_name_len = pack('!B', 9)
   RPC_type = pack('!B', 0)
   payload_length = pack('!i', 41)
   RPC_req_name = pack('!9s', "discrenew")
   guid = pack('!32s', client_guid)
   renewal_msg = RPC_name_len + RPC_type + payload_length + RPC_req_name + guid
   while True:
        time.sleep(RENEWAL_TIME)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(server_addr)
            sock.settimeout(30)
            sock.sendall(renewal_msg)
            if key:
                ack = sock.recv(23) #Receive ack with 8-byte nonce
                if check_ack(ack):
                    msg = challenge_response(ack[15:])
                    sock.sendall(msg)
                    ack = sock.recv(6) #Receive ack of challenge response
            else:
                ack = sock.recv(6)
            if not check_ack(ack):
                print "Renewal error: invalid ack received from discovery service"
                break
        except socket.timeout:
            print "Renewal error: renewal exchange with discovery service timed out"
            break
        except socket.error:
            print "Renewal error: renewal exchanged with discovery service failed"
            break
        finally:
            sock.close()

def challenge_response(nonce):
    """
    Concatenates a nonce and the client's guid and signs it using the client's
    private key. The resulting signature is returned.
    """
    h = SHA.new(nonce + client_guid)
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(h)
    return signature

def service_resolved(*args):
    """
    Handles a new connection to a zeroconf service. If the service is a 
    gdp discovery service, a connection RPC message is sent to the server
    and a renewal message is sent once every RENEWALTIME.
    If the service is not a discovery service, then this method returns.
    """
    name = args[2]
    address = args[7]
    port = args[8]

    if name != "GDP_discovery" or not is_ip(address):
        #Only connect to GDP_discovery ip addresses
        if name != "GDP_discovery":
            print "service_resolved: " + name + " is not GDP_discovery"
        if not is_ip(address):
            print "service_resolved: " + address + " is not an ip address"
        return

    print "service resolved"
    print "name: " + str(name)
    print "address: ", str(address)
    print "port: ", str(port)

    #Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #Connect the socket to the port where the server is listening
    server_address = (args[7], args[8])
    print >>sys.stderr, 'connecting to %s port %s' % server_address
    sock.connect(server_address)
    msg = conn_msg()
    sock.settimeout(30)
    ack = None
    try:
        #Send initial connection message
        sock.sendall(msg)

        #Look for ACK
        if key:
            ack = sock.recv(23) #Receive ack with 8-byte nonce
            if check_ack(ack):
                msg = challenge_response(ack[15:])
                sock.sendall(msg)
                ack = sock.recv(6) #Receive ack of challenge response
        else:
            ack = sock.recv(6) #Receive ack with no nonce
    except socket.timeout:
        print "Connection with discovery service timed out"
    finally:
        sock.close()
    if ack and check_ack(ack):
        print "Connection to discovery service successful"
        send_renewals(server_address)
    else:
         print "Nonexistent or unsuccessful ack from discovery service"

def print_error(*args):
    print 'error_handler'
    print args[0]
    
def myhandler(interface, protocol, name, stype, domain, flags):
    print "Found service '%s' type '%s' domain '%s' " % (name, stype, domain)
    server.ResolveService(interface, protocol, name, stype, 
        domain, avahi.PROTO_UNSPEC, dbus.UInt32(0), 
        reply_handler=service_resolved, error_handler=print_error)

def advertise(guid, info_log, output_log=None, input_log=None, gdp_router=None, key_file=None):
    """
    Advertises a client to discovery services on the local network. Once a discovery service
    is found, a connection message is sent. After initial connection is made, a renewal
    message will be sent once every RENEWALTIME seconds.
    """
    global client_guid, client_info_log, client_output_log, client_input_log, key
    client_guid = guid
    client_info_log = info_log
    client_output_log = output_log
    client_input_log = input_log
    if key_file:
        key = RSA.importKey(open(key_file).read())
    if gdp_router:
        gdp.gdp_init(gdp_router)
    else:
        gdp.gdp_init()
    sbrowser.connect_to_signal("ItemNew", myhandler)
    gobject.MainLoop().run()
