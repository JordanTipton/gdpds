#!/usr/bin/env python

"""
A gdp disocvery server which advertises itself on a local network, receives RPC messages
from clients, and logs those clients' information in a MySQL database. If the server 
does not receive a renewal RPC message from a client within TIMEOUT seconds after its 
last message, the client is removed from the database.

Client information is obtained by reading the client's specified info_log. Clients with
private keys are authenticated and info_logs containing valid certificates are
verified. Clients are logged in the discovery database even if they are not certified
or authenticated, but the clients table describes whether they are certified and/or
authenticated.

### Usage ###

Python API example:
> discovery.server.run(router_host='129.168.4.2', router_port=8007, user="gdp_discovery",
                       passwd="gdp_disc438", host="localhost", name="discovery_db",
                       bootstrap="bootstrap.ring.cx:4222", trusted_certificates=certs)

Python API example using defaults and no trusted certificates:
> discovery.server.run()

Command line example using defaults and trusted certificates file:
> discovery/server.py -c 'trusted_certs.txt'

Public interface:
* Run:
  Runs the discovery server. Logs into the discovery database using the specified login
  information (or defaults if none is provided), accesses the GDP using the specified
  GDP router information, and verifies info_log certificates using the provided list
  of certificates.
* Main:
  Command line wrapper for run() using the interface described in main().

Internal structure and key properties:
* Database:
  The discovery database is designed to be ephemeral in nature. It is maintained in
  real time and previously stored state is discarded upon discovery server startup.
  
  The discovery service logs client information using 3 tables:
  - clients: contains client-specific information such as guid, IP, auth/cert status
  - capabilities: contains guid:capability mappings to be used in queries
  - permissions: contains guid:permission mappings to be used in queries

  Client public keys are not stored in the database as they are too large. Instead,
  a "keys" directory is created which contains the currently logged clients'
  public keys.

* RPC interface:
  Clients communicate with the server using a RPC interface. Details on the interface
  can be found in the document "discovery_rpc.html"
"""

import sys
# append parent directories to path so can import gdp from gdpds or its parent
sys.path.append("../")
sys.path.append("../../")
import gdp
import os
import argparse
import socket
import dbus
import gobject
import avahi
from dbus.mainloop.glib import DBusGMainLoop
import time
from struct import pack, unpack
import MySQLdb
import threading
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from optparse import OptionParser
import shutil
import random
from OpenSSL import crypto
import subprocess
import datetime
from urllib2 import urlopen
import requests
import json
import info_log_reader

DEBUG = True # Prints database tables at TIMEOUT_FREQ if True

public_ip = urlopen("http://ip.42.pl/raw").read()

# Zeroconf constants
SERVICE_HOST = "" # Host to publish records for, default to localhost
SERVICE_PORT = 7990

# ClientLogger server constants
HOST = ''
PORT = 7990
TIMEOUT = 120 # Number of seconds a device will remain logged in the database without a transmission
TIMEOUT_FREQ = 5 # Number of seconds before each round of device removal
SIGNATURE_LEN = 128 # Size of signature from client
PKEY_LEN = 271 # Size of public key .pem file

# DHT Service constants
DHT_PORT = 7991

# Shared dictionary mapping connected clients to their last transmission time
guid_times = {}
guid_times_lock = threading.Lock()

# Reads info logs
log_reader = None

# A store containing trusted certificates
trusted_cert_store = None

class ZC_Service:
    """
    Zeroconf service which advertises the presence of the discovery service on the subnet
    """
    serviceName = "GDP_discovery"
    serviceType = "_gdp-discovery._tcp"
    serviceVersion = "1.0"
    def __init__(self, serviceHost, servicePort):
        self.serviceHost = serviceHost
        self.servicePort = servicePort
        self.serviceTXT = []
        self.serviceDomain = "" # Domain to publish on, default to .local
        self.group = None #our entry group
        self.rename_count = 12 # Counter so we only rename after collisions a sensible number of times
        self.bus = None 
        self.server = None

    def add_service(self):
        if self.group is None:
            self.group = dbus.Interface(
                    self.bus.get_object( avahi.DBUS_NAME, self.server.EntryGroupNew()),
                    avahi.DBUS_INTERFACE_ENTRY_GROUP)
            self.group.connect_to_signal('StateChanged', self.entry_group_state_changed)

        print "Adding service '%s' of type '%s' ..." % (self.serviceName, self.serviceType)

        self.group.AddService(
                              avahi.IF_UNSPEC,    #interface
                              avahi.PROTO_UNSPEC, #protocol
                              dbus.UInt32(0),                  #flags
                              self.serviceName, self.serviceType,
                              self.serviceDomain, self.serviceHost,
                              dbus.UInt16(self.servicePort),
                              avahi.string_array_to_txt_array(self.serviceTXT))
        self.group.Commit()

    def remove_service(self):
        if not group is None:
            group.Reset()

    def server_state_changed(self, state):
        if state == avahi.SERVER_COLLISION:
            print "WARNING: Server name collision"
            self.remove_service()
        elif state == avahi.SERVER_RUNNING:
            self.add_service()

    def entry_group_state_changed(self, state, error):
        print "state change: %i" % state

        if state == avahi.ENTRY_GROUP_ESTABLISHED:
            print "Service established."
        elif state == avahi.ENTRY_GROUP_COLLISION:

            self.rename_count -= 1
            if self.rename_count > 0:
                name = self.server.GetAlternativeServiceName(name)
                print "WARNING: Service name collision, changing name to '%s' ..." % name
                self.remove_service()
                self.add_service()
            else:
                print "ERROR: No suitable service name found after %i retries, exiting." % n_rename
                main_loop.quit()
        elif state == avahi.ENTRY_GROUP_FAILURE:
            print "Error in group state changed", error
            main_loop.quit()
            return

    def run(self):
        """Publishes zeroconf service"""
        print "publishing zeroconf service"
        DBusGMainLoop( set_as_default=True )

        main_loop = gobject.MainLoop()
        self.bus = dbus.SystemBus()

        self.server = dbus.Interface(
                                     self.bus.get_object( avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER ),
                                     avahi.DBUS_INTERFACE_SERVER )

        self.server.connect_to_signal( "StateChanged", self.server_state_changed )
        self.server_state_changed(self.server.GetState() )

        try:
            main_loop.run()
        except KeyboardInterrupt:
            pass

        if not self.group is None:
            self.group.Free()

class ClientLogger:
    """
    Provides methods for updating the discovery service's database with client
    information
    """
    def __init__(self, db_user, db_passwd, db_host, db_name):
        self.db = None
        self.db_user = db_user
        self.db_passwd = db_passwd
        self.db_host = db_host
        self.db_name = db_name

    def open_database(self): 
        self.db = MySQLdb.connect(self.db_host, self.db_user, self.db_passwd, self.db_name)

    def write_pkey(self, guid, pkey):
        """
        Writes client's public key to the "keys" directory. keys are named using their
        32-byte guid and are written in pem format.
        """
        if not os.path.exists("keys"):
            os.makedirs("keys")
        filename = guid + ".pem"
        path = "keys"
        with open(os.path.join(path, filename), "w") as f:
            f.write(pkey)

    def read_pkey(self, guid):
        """
        Reads a client's key from the "keys" directory and returns a key object
        """
        filename = guid + ".pem"
        path = "keys"
        with open(os.path.join(path, filename), "r") as f:
            return RSA.importKey(f.read())

    def delete_pkey(self, guid):
        """
        Deletes a client's public key from the "keys" directory
        """
        filename = guid + ".pem"
        path = "keys"
        os.remove(os.path.join(path, filename))

    def delete_all_pkeys(self):
        """
        Deletes all keys from the "keys" directory
        """
        if os.path.exists("keys"):
            shutil.rmtree("keys")

    def remove_client(self, device_GUID, remove_capabilities=True, \
                      remove_permissions=True, remove_info=True):
        """
        Removes a client and its information from the discovery database
        """
        try:
            cursor = self.db.cursor()
            if remove_info:
                sql = """DELETE FROM `clients`
                         WHERE client_guid = '%s';""" % device_GUID
                cursor.execute(sql)

            if remove_capabilities:
                #delete old capabilities
                sql = """DELETE FROM `capabilities`
                         WHERE client_guid = '%s';""" % device_GUID
                cursor.execute(sql)

            if remove_permissions:
                #delete old permissions
                sql = """DELETE FROM `permissions`
                         WHERE `client_guid` = '%s';""" % device_GUID
                cursor.execute(sql)
            self.db.commit()
            cursor.close()
        except MySQLdb.Error, e:
            self.db.rollback()
            print "Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        #TODO: push update to subscribing discover services

    def remove_all_clients(self):
        """
        Removes all client and their information from the discovery database
        """
        try:
            cursor = self.db.cursor()
            cursor.execute("DELETE FROM clients;")
            cursor.execute("DELETE FROM capabilities;")
            cursor.execute("DELETE FROM permissions;")
            self.db.commit()
            cursor.close()
        except MySQLdb.Error, e:
            self.db.rollback()
            print "Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)

    def is_authenticated(self, guid):
        """
        Returns true if a client has been authenticated else false
        """
        authenticated = 0
        try:
            cursor = self.db.cursor()
            sql = """SELECT `authenticated` FROM `clients`
                     WHERE `client_guid` = '%s';""" % guid
            cursor.execute(sql)
            authenticated, = cursor.fetchone()
            self.db.commit()
            cursor.close()
        except MySQLdb.Error, e:
            self.db.rollback()
            print "Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        return authenticated

    def is_certified(self, guid):
        """
        Returns true if a client's info log has a valid certificate else false
        """
        certified = 0
        try:
            cursor = self.db.cursor()
            sql = """SELECT `certified` FROM `clients`
                     WHERE `client_guid` = '%s';""" % guid
            cursor.execute(sql)
            certified, = cursor.fetchone()
            self.db.commit()
            cursor.close()
        except MySQLdb.Error, e:
            self.db.rollback()
            print "Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        return certified

    def verify_certificate_chain(self, certificate_str):
        """
        Verifies a certificate using the trusted certificates contained in
        trusted_cert_store
        """
        if not certificate_str:
            return False
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_str)
        try:
            store_context = crypto.X509StoreContext(trusted_cert_store, certificate)
            store_context.verify_certificate() # returns None if valid
            return True
        except Exception as e:
            print(e)
            return False

    def dht_put(self, device_guid, info_log, input_log, output_log):
        if DEBUG:
            print "dht_put: device_guid = %s, info_log = %s, input_log = %s, output_log = %s" % \
                    (device_guid, info_log, input_log, output_log)
        time = str(datetime.datetime.now())
        #time = datetime.datetime.now()
        #time = str(time.year) + "-" + str(time.month) + "-" + str(time.day) + "T" + \
        #       str(time.hour) + ":" + str(time.minute) + ":" + str(time.second)
        data = {"guid": device_guid, "datetime": time, "logger_ip": public_ip, \
                "input_log": input_log, "output_log": output_log}
        r = requests.put("http://localhost:" + str(DHT_PORT) + "/rest/v1/devices/" + info_log, data=data)
        print "dht_put: completed put to DHT"
        if r.status_code == 200:
            result = [{str(k): str(v) for k, v in json.loads(str(e)).items()} for e in r.json()]
            print "dht_put: returning " + str(result)
            return  result
        else:
            print "failed to log device with DHT"
            return False

    def dht_get(self, info_log):
        r = requests.get("http://localhost:" + str(DHT_PORT) + "/rest/v1/devices/" + info_log)
        if r.status_code == 200:
            return [{str(k): str(v) for k, v in json.loads(str(e)).items()} for e in r.json()]
        else:
            return False

class DhtNode(threading.Thread):
    """
    Manages server's connection to a discovery DHT network
    """
    def __init__(self, bootstrap, input_bootstrap_port=4224):
        threading.Thread.__init__(self)
        self.bootstrap = bootstrap # example: "bootstrap.ring.cx:4222"
        self.input_bootstrap_port = input_bootstrap_port
        
    def run(self):
        # Must make a system call to run dht_service because it requires python3
        if self.bootstrap != None:
            subprocess.call(["python3", "gdpds/dht_service.py", "-b", self.bootstrap, \
                    "-p", str(self.input_bootstrap_port), "-P", str(DHT_PORT)])
        else:
            subprocess.call(["python3", "gdpds/dht_service.py", "-p", str(self.input_bootstrap_port),
            		"-P", str(DHT_PORT)])

class ConnectionLogger(threading.Thread, ClientLogger):
    """
    Manages RPC handling for a single client
    """
    def __init__(self, db_user, db_passwd, db_host, db_name, connection, addr):
        threading.Thread.__init__(self)
        ClientLogger.__init__(self, db_user, db_passwd, db_host, db_name)
        self.connection = connection
        self.addr = addr
        self.guid = None

    def generic_success_ack(self):
        """
        Returns a generic string representing an ACK-RPC
        """
        ack_name_length = 0
        ack_type = 1
        ack_length = 6
        ack = pack('!BBi', ack_name_length, ack_type, ack_length)
        return ack

    def generic_nak_c(self):
        """
        Returns a generic string representing a NAK-C-RPC
        """
        ack_name_length = 0
        ack_type = 2
        ack_length = 6
        ack = pack('!BBi', ack_name_length, ack_type, ack_length)
        return ack

    def generic_nak_s(self):
        """
        Returns generic string representing a NAK-S-RPC
        """
        ack_name_length = 0
        ack_type = 3
        ack_length = 6
        ack = pack('!BBi', ack_name_length, ack_type, ack_length)
        return ack

    def send_generic_success_ack(self):
        """
        Sends a generic ACK to the client
        """
        try:
            self.connection.settimeout(10)
            self.connection.send(self.generic_success_ack())
            self.connection.settimeout(None)
        except socket.timeout:
            print "Timed out sending ack to client"
    
    def send_generic_nak_c(self):
        """
        Sends a generic NAK-C-RPC to the client
        """
        try:
            self.connection.settimeout(10)
            self.connection.send(self.generic_nak_c())
            self.connection.settimeout(None)
        except socket.timeout:
            print "Timed out sending nak-c to client"

    def send_generic_nak_s(self):
        """
        Sends a gneeric NAK-S-RPC to the client
        """
        try:
            self.connection.settimeout(10)
            self.connection.send(self.generic_nak_s())
            self.connection.settimeout(None)
        except socket.timeout:
            print "Timed out sending nak-s to client"
    
    def generate_nonce_msg(self):
        """
        Returns a challenge (RPC ACK) containing an 8-byte nonce
        """
        nonce = pack('!8s', ''.join([str(random.randint(0, 9)) for i in range(8)]))
        ack_name_length = pack('!B', 9)
        ack_type = pack('!B', 1)
        ack_name = pack('!9s', 'challenge')
        payload_length = pack('!i', 17)
        nonce_msg = ack_name_length + ack_type + ack_name + payload_length + nonce
        return nonce, nonce_msg

    def check_challenge_response(self, challenge, signature, device_pkey):
        """
        Returns true if the device's signature matches with a challenge
        and the device's public key otherwise returns false
        """
        h = SHA.new(challenge)
        verifier = PKCS1_v1_5.new(device_pkey)
        if verifier.verify(h, signature):
            return True
        else:
	    return False

    def verify_client(self):
        """
        Requests a signature from the client and verifies that the client has
        its private key. Returns true if the client's identity is authenticated
        and false otherwise.
        """
        nonce, nonce_msg = self.generate_nonce_msg()
        challenge = nonce + self.guid
        try:
            self.connection.settimeout(30)
            print "challenge = " + challenge
            self.connection.send(nonce_msg)
            challenge_response = self.connection.recv(SIGNATURE_LEN)
            self.connection.settimeout(None)
            if self.check_challenge_response(challenge, challenge_response, 
                                             self.read_pkey(self.guid)):
                return True
            else:
                return False
        except socket.timeout:
            print "Timed out verifying client"
            return False

    def conn(self, data):
        """
        Handles a connection RPC request.
        Authenticates client's identity, reads the client's corresponding info log
        and stores its information in the discovery database.

        Parameters:
        data - connection request RPC message, beginning with the connection type
        """
        global guid_times, guid_times_lock
        print "Received a conn request from " + str(self.addr)
        conn_type, = unpack('!B', data[0])
        device_GUID, = unpack('!32s', data[1 : 33])
        device_info_log, = unpack('!43s', data[33 : 76])
        device_input_log = None
        device_output_log = None
        device_pkey = None
        self.guid = device_GUID

        # Input only device
        if conn_type == 0x00 or conn_type == 0x80:
            device_input_log, = unpack('!43s', data[76 : 119])
            if conn_type == 0x80:
                device_pkey, = unpack('!' + str(PKEY_LEN) + 's', data[119 :])

        # Output only device
        if conn_type == 0x01 or conn_type == 0x81:
            device_output_log, = unpack('!43s', data[76 : 119])
            if conn_type == 0x81:
                device_pkey, = unpack('!' + str(PKEY_LEN) + 's', data[119 :])

        # Input and output device
        if conn_type == 0x02 or conn_type == 0x82:
            device_input_log, = unpack('!43s', data[76 : 119])
            device_output_log, = unpack('!43s', data[119 : 162])
            if conn_type == 0x82:
                device_pkey, = unpack('!' + str(PKEY_LEN) + 's', data[162 :])

        authenticated = True if device_pkey else False
        capabilities, permissions, pkeys, certificate = log_reader.read(device_info_log)

        if self.verify_certificate_chain(certificate):
            certified = True
            print "client certified"
        else:
            certified = False
            print "client failed certificate verification"

        if authenticated:
            if device_pkey not in pkeys:
                self.send_generic_nak_c()
                return

            # write public key to public key store
            self.write_pkey(self.guid, device_pkey)
        
            if self.verify_client():
                self.send_generic_success_ack()
            else:
                print "client failed verification"
                self.send_generic_nak_c()
                return
        else:
            print "client not authenticated"
            self.send_generic_success_ack()

        # delete old capabilities and permissions
        self.remove_client(device_GUID, remove_info=False)
        self.dht_put(device_GUID, device_info_log, device_input_log, device_output_log)
        try:
            cursor = self.db.cursor()
            #insert client info into clients table, replacing old data with new
            client_vals = (device_GUID, self.addr[0], device_info_log, \
                           device_input_log if device_input_log else "NULL", \
                           device_output_log if device_output_log else "NULL", \
                           "1" if authenticated else "0", \
                           "1" if certified else "0")
            sql = """INSERT INTO `clients`
                     (`client_guid`, `client_ip`, `info_log`, `input_log`, `output_log`, `authenticated`, `certified`)
                     VALUES
                     ('%s', '%s', '%s', '%s', '%s', '%s', '%s')
                     ON DUPLICATE KEY UPDATE
                     `client_guid` = VALUES(`client_guid`),
                     `client_ip` = VALUES(`client_ip`),
                     `info_log` = VALUES(`info_log`),
                     `input_log` = VALUES(`input_log`),
                     `output_log` = VALUES(`output_log`),
                     `authenticated` = VALUES(`authenticated`),
                     `certified` = VALUES(`certified`);""" % client_vals
            cursor.execute(sql)
            
            #insert client info into capabilities table
            sql = """INSERT INTO `capabilities`
                     (`capability`, `client_guid`)
                     VALUES """
            for capability in capabilities:
                sql += "('" + capability + "', '" + device_GUID + "'), "
            sql = sql[:-2] + ";"
            cursor.execute(sql)

            #insert client info into permissions table
            sql = """INSERT INTO `permissions`
                     (`permission`, `client_guid`)
                     VALUES """
            for permission in permissions:
                sql += "('" + permission + "', '" + device_GUID + "'), "
            sql = sql[:-2] + ";"
            cursor.execute(sql)
            self.db.commit()
            cursor.close()

        except MySQLdb.Error, e:
            self.db.rollback()
            print "Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        guid_times_lock.acquire()
        guid_times[device_GUID] = time.time()
        guid_times_lock.release()
        self.send_generic_success_ack()

    def renew(self, data):
        """
        Handles a gdp discovery renewal RPC call from a client. Updates the
        guid_times dictionary with the current time to restart the timout
        clock for a particular client.

        Paramters:
        data - gdp discovey renewal RPC call starting with the client's guid
        """
        global guid_times, guid_times_lock
        print "Received a renew request from " + str(self.addr)
        device_GUID, = unpack('!32s', data[0 : 32])
        self.guid = device_GUID
        try:
            cursor = self.db.cursor()
            sql = """SELECT C.info_log 
                     FROM clients AS C 
                     WHERE C.client_guid = '%s';""" % device_GUID
            cursor.execute(sql)
            info_log, = cursor.fetchone()
            print "info_log = " + str(info_log)

            sql = """SELECT C.input_log
                     FROM clients AS C 
                     WHERE C.client_guid = '%s';""" % device_GUID
            cursor.execute(sql)
            input_log, = cursor.fetchone()
            print "input_log = " + str(input_log)

            sql = """SELECT C.output_log 
                     FROM clients AS C
                     WHERE C.client_guid = '%s';""" % device_GUID
            cursor.execute(sql)
            output_log, = cursor.fetchone()
            print "output_log = " + str(output_log)
            cursor.close()
        except MySQLdb.Error, e:
            print "Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)
        if not self.is_authenticated(self.guid) or self.verify_client():
            self.dht_put(device_GUID, info_log, input_log, output_log)
            guid_times_lock.acquire()
            guid_times[device_GUID] = time.time()
            guid_times_lock.release()
            self.send_generic_success_ack()
        else:
            print "client failed verification"
            self.send_generic_nak_c()
            return       

    def delete(self, data):
        """
        Handles a gdp discovery delete RPC call from a client. Removes the
        client from the discovery database, removes its guid from guid_times,
        and deletes the client's public key from the "keys" directory
        
        Parameters:
        data- gdp discovery delete RPC call starting with the client's guid
        """
        global guid_times, guid_times_lock
        print "Received a delete request from " + str(self.addr)
        device_GUID, = unpack('!32s', data[0 : 32])
        self.guid = device_GUID
        if not self.is_authenticated(self.guid) or self.verify_client():
            self.remove_client(device_GUID)
            guid_times_lock.acquire()
            del guid_times[device_GUID]
            guid_times_lock.release()
            self.send_generic_success_ack()
            self.delete_pkey(self.guid)
        else:
            print "client failed verification"
            self.send_generic_nak_c()
            return
        
    def run(self):
        """
        Handles any gdp discovery RPC message. Reads the name of the RPC message
        and dispatches the message contents to the proper handler.
        """
        self.open_database()
        self.connection.settimeout(10)
        failed = False
        try:
            msg = self.connection.recv(6) # Every connection should have 6 byte header

            call_name_length, = unpack('!B', msg[0])
            call_type, = unpack('!B', msg[1])
            data_length, = unpack('!i', msg[2:6])
            call_handler = {
                "discconn": self.conn,
                "discrenew": self.renew,
                "discdelete": self.delete
            }
            data = self.connection.recv(data_length)
        except socket.timeout:
            print "Client timed out"
            failed = True
            self.send_generic_nak_c()
        if not failed:
            call_handler[data[:call_name_length]](data[call_name_length:])
        self.connection.close()
        self.db.close()

class TimeoutLogger(threading.Thread, ClientLogger):
    """
    A client logger which can execute a time_entries loop, removing old clients from
    the discovery database.
    """
    def __init__(self, db_user, db_passwd, db_host, db_name):
        threading.Thread.__init__(self)
        ClientLogger.__init__(self, db_user, db_passwd, db_host, db_name)

    def run(self):
        """
        Delete clients which have not renewed their registration for more than
        TIMEOUT seconds in the database
        """
        global guid_times, guid_times_lock
        print "running timeout logger"
        self.open_database()
        self.remove_all_clients() # Clear any old entries from prior session
        self.delete_all_pkeys() # Delete any old keys from prior session
        cursor = self.db.cursor()
        while True:
            time.sleep(TIMEOUT_FREQ)
            if DEBUG:
                print "timeout_entries: doing a round of timeouts. guidtimes: " + str(guid_times)
            for guid, last_time in guid_times.items():
                if time.time() - last_time > TIMEOUT:
                    if self.is_authenticated(guid):
                        self.delete_pkey(guid)
                    self.remove_client(guid)
                    if DEBUG:
                        print "%s timed out" % guid
                    guid_times_lock.acquire()
                    del guid_times[guid]
                    guid_times_lock.release()
            if DEBUG:
                cursor.execute("SELECT * FROM clients;")
                result = cursor.fetchall()
                print "timeout_entries: clients table is now: " + str(result)
                cursor.execute("SELECT * FROM capabilities;")
                result = cursor.fetchall()
                print "timeout_entries: capabilities table is now: " + str(result)
                cursor.execute("SELECT * FROM permissions;")
                result = cursor.fetchall()
                print "timeout_entries: permissions table is now: " + str(result)
                self.db.commit()

def listen(router_host, router_port, db_user, db_passwd, db_host, db_name):
    """
    Listens for new connections to the discovery server. Creates a ConnectionLogger
    instance for each received connection and handles the RPC request in a new thread.
    """
    global log_reader
    log_reader = info_log_reader.InfoLogReader(router_host, router_port)
            
    #Listen for new RPC requests
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    while True:
        c, addr = s.accept()
        print "Got connection from", addr
        connection_logger = ConnectionLogger(db_user, db_passwd, db_host, db_name, c, addr)
        connection_logger.start()

def setup_database(db_user, db_passwd, db_host, db_name):
    """
    Logs into a MySQL using the specified login information and creates a database
    and its tables if they do not already exist.
    """
    # Setup database
    try:
        # Create database if it does not exist
        db = MySQLdb.connect(db_host, db_user, db_passwd)
        cursor = db.cursor()
        cursor.execute('CREATE DATABASE IF NOT EXISTS ' + db_name)
        db.commit()
        cursor.close()
        db.close()
    
        # Open database
        db = MySQLdb.connect(db_host, db_user, db_passwd, db_name)
        cursor = db.cursor()
        sql = """CREATE TABLE IF NOT EXISTS clients (
                 client_guid CHAR(32) NOT NULL,
                 client_ip VARCHAR(15),
                 info_log CHAR(43),
                 input_log CHAR(43) DEFAULT NULL,
                 output_log CHAR(43) DEFAULT NULL,
                 authenticated BOOLEAN DEFAULT FALSE,
                 certified BOOLEAN DEFAULT FALSE,
                 KEY (client_guid))"""
        cursor.execute(sql)
        sql = """CREATE TABLE IF NOT EXISTS capabilities (
                 capability VARCHAR(767),
                 client_guid CHAR(32),
                 KEY (capability, client_guid))"""
        cursor.execute(sql)
        sql = """CREATE TABLE IF NOT EXISTS permissions (
                 permission VARCHAR(767),
                 client_guid CHAR(32),
                 KEY (permission, client_guid))"""
        cursor.execute(sql)
        db.commit()
        cursor.close()
        db.close()
    except MySQLdb.Error, e:
        print "Error %d: %s" % (e.args[0], e.args[1])
        sys.exit(1)

def run(router_host=None, router_port=None, user="gdp_discovery",
        passwd="gdp_disc438", host="localhost", name="discovery_db",
        bootstrap=None, trusted_certificates=None):
    """
    Runs the gdp discovery server. Starts three threads:
    1. One thread runs the zeroconf zerfice, which advertises the presence
       of the discovery server on the local network
    2. One thread listens for incoming RPC requests from clients/gateways
    3. One thread runs the a TimeoutLogger instance, which maintains
       a list of registered clients and deletes those which timeout from
       the discovery database

    Paramters:
    router_host - hostname of the gdp router (string)
    router_port - port of the gdp router (int)
    user - username for discovery database
    passwd - password for discovery database
    host - host of the discovery database
    name - name of the discovery database
    bootstrap - "ip:port" of a dht_service bootstrap node
    trusted_certificates - list of trusted certificates in string format,
                           which will be used to verify info_log
                           certificates
    """
    global trusted_cert_store
    trusted_cert_store = crypto.X509Store()
    for cert in trusted_certificates:
        cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        trusted_cert_store.add_cert(cert_obj)

    setup_database(user, passwd, host, name)
    zc_child = os.fork()
    if zc_child:
        timeout_logger = TimeoutLogger(user, passwd, host, name)
        timeout_logger.start()
        dht_node = DhtNode(bootstrap)
        dht_node.start()
        listen(router_host, router_port, user, passwd, host, name)
        waitpid(zc_child, 0)
    else:
        zc_service = ZC_Service(SERVICE_HOST, SERVICE_PORT)
        zc_service.run()

def main():
    """
    Command line interface used to call run()
    """
    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-r", "--router", dest="router",
                      help="use gdp router specified in the form ip:port")
    parser.add_option("-u", "--user", dest="user", default="gdp_discovery",
                      help="specify discovery database user")
    parser.add_option("-p", "--passwd", dest="passwd", default="gdp_disc438",
                      help="specify discovery database password")
    parser.add_option("-H", "--host", dest="host", default="localhost",
                      help="specify discovery database host")
    parser.add_option("-n", "--name", dest="name", default="discovery_db",
                      help="specify discovery database name")
    parser.add_option("-b", "--bootstrap", dest="bootstrap",
                      help="ip:port of a dht_service bootstrap node")
    parser.add_option("-c", "--certificates_file", dest="certs_file",
                      help="specify a file containing trusted certificates")
    (options, args) = parser.parse_args()
    if options.router:
        router = options.router.split(":")
        router_host = router[0]
        router_port = int(router[1])
    else:
        router_host = None
        router_port = None

    #load trusted certificates into a list
    trusted_certs = []
    if options.certs_file:
        with open(options.certs_file) as f:
            cert = ""
            for line in f:
                if line == "-----END CERTIFICATE-----\n":
                    cert += line
                    trusted_certs.append(cert)
                    cert = ""
                else:
                    cert += line

    run(router_host, router_port, options.user, options.passwd, options.host, 
        options.name, options.bootstrap, trusted_certs)
    
if __name__ == '__main__':
    main()
