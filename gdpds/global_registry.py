#!/usr/bin/env python

"""
A HTTP server which handles get requests for devices using the GDP and handles put requests
for registering device classes (all devices described by a particular info log) with this
global registry service.


### Public restful interface ###

GET /rest/v1/devices:
    GET requests must specify capability, permission, and active_since query parameters.
    All devices which have been logged in the DHT since active_since, which have all of the queried
    capabilities and which have at least one of the queried permissions will be returned. If the query
    parameter 'capability' is set to 'any' devices with any capability will be returned.

    Example GETrequest: 
    http://gdp.cs.berkeley.edu:11780/rest/v1/devices?capability=any&permission=p1234&permission=public&active_since=2016-12-3 22:08:24.130922

PUT /rest/v1/deviceclasses:
    PUT requests must specify an unregistered info log in the form data. The specified info log
    will be read and stored in the global registry's database.

    Example HTTP PUT request:
    http://gdp.cs.berkeley.edu:11780/rest/v1/deviceclasses
    form data:
    info_log: edu.berkeley.eecs.jordan.nov14.pwrbld_il1

### Internal structure and key properties ###

The global registry uses a two-step filtering process to respond to GET requests:
1. The registry's MySQL database is searched for all info logs which meet the criteria
   specified in the GET request
2. The registry gets all of the devices logged in the discovery DHT for each info log
   found in (1). Of the devices found in the DHT, only those which have datetimes
   after the 'active_since' query parameter are returned

A MySQL database is used to store information about registered device classes (info logs):
- a 'capabilities' table stores (info log name, capability string) pairs
- a 'permissions' table stores (info log name, permission string) pairs

The global registry runs a python3 dht_service to access the discovery DHT
"""

import sys
# append parent directories to path so can import gdp depending on where it is called from
sys.path.append("../")
sys.path.append("../../")
sys.path.append("../../../")
import gdp
import argparse
import json
import MySQLdb
from optparse import OptionParser
from flask import Flask, request
from flask_restful import Resource, Api
import info_log_reader
import datetime
import threading
import subprocess
import requests

app = Flask(__name__)
api = Api(app)
log_reader = None
class_repository = None
device_repository = None
DHT_PORT = 7992

class Device(Resource):
    def get(self):
        capabilities = request.args.getlist("capability")
        permissions = request.args.getlist("permission")
        active_since = request.args.get("active_since")
        print "Device - get: capabilities = %s, permissions = %s, active_since = %s" % \
                (str(capabilities), str(permissions), str(active_since))
        result = device_repository.get_devices(capabilities, permissions, active_since)
        print "returning result: " + str(result)
        return result

class DeviceClass(Resource):
    def put(self):
        form_data = json.loads(json.dumps(request.form))
        info_log = form_data["info_log"]
        print "DeviceClass - put: info_log = " + info_log
        capabilities, permissions = log_reader.read(info_log)[:2]
        class_repository.store_new(info_log, capabilities, permissions)
        result = class_repository.get(capabilities, permissions)
        print "returning result: " + str(result)
        return result

api.add_resource(Device, "/rest/v1/devices")
api.add_resource(DeviceClass, "/rest/v1/deviceclasses")

class DeviceClassRepository:
    """
    Class providing access to information about device classes.
    A device class is all of the devices which are described by a specific info log
    """
    def __init__(self, db_user, db_passwd, db_host, db_name):
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
            self.db = MySQLdb.connect(db_host, db_user, db_passwd, db_name)
            cursor = self.db.cursor()
            sql = """CREATE TABLE IF NOT EXISTS capabilities (
                     capability VARCHAR(767),
                     info_log CHAR(43),
                     KEY (capability, info_log))"""
            cursor.execute(sql)
            sql = """CREATE TABLE IF NOT EXISTS permissions (
                     permission VARCHAR(767),
                     info_log CHAR(43),
                     KEY (permission, info_log))"""
            cursor.execute(sql)
            print "DeviceClassRepo init: executed sql"
            #db.commit()
            #print "DeviceClassRepo init: committed"
        except MySQLdb.Error, e:
            print "Error %d: %s" % (e.args[0], e.args[1])
            #sys.exit(1)

    def store_new(self, info_log, capabilities, permissions):
        print "store_new: " + info_log
        try:
            cursor = self.db.cursor()
            #delete old capabilities info
            sql = """DELETE FROM `capabilities`
                     WHERE `info_log` = '%s';""" % info_log
            cursor.execute(sql)

            #delete old permissions info
            sql = """DELETE FROM `permissions`
                     WHERE `info_log` = '%s';""" % info_log
            cursor.execute(sql)

            #insert info into capabilities table
            sql = """INSERT INTO `capabilities`
                     (`capability`, `info_log`)
                     VALUES """
            for capability in capabilities:
                sql += "('" + capability + "', '" + info_log + "'), "
            sql = sql[:-2] + ";"
            cursor.execute(sql)

            #insert info into permissions table
            sql = """INSERT INTO `permissions`
                     (`permission`, `info_log`)
                     VALUES """
            for permission in permissions:
                sql += "('" + permission + "', '" + info_log + "'), "
            sql = sql[:-2] + ";"
            cursor.execute(sql)
            self.db.commit()
            cursor.close()

        except MySQLdb.Error, e:
            self.db.rollback()
            print "Error %d: %s" % (e.args[0], e.args[1])
            #sys.exit(1)

    def get(self, capabilities, permissions):
        # query dht for guids after have the relevant info_logs
        """
        Return set of guids which have each capability in capabilities and
        at least one permission in permissions
        """
        print "DeviceClassRepository get: capabilities = %s, permissions = %s" % (capabilities, permissions)
        def with_capability(c):
            """
            Return set of guids wich have capability c
            """
            if c == "any":
                sql = """SELECT c.info_log
                         FROM capabilities c"""
            else:
                sql = """SELECT c.info_log 
                         FROM capabilities c
		         WHERE c.capability = '%s'""" % c
            cursor = self.db.cursor()
            cursor.execute(sql)
            results = cursor.fetchall()
            classes = set([])
            for result in results:
                classes.add(result[0])
            self.db.commit()
            cursor.close()
            print "with_capability(%s): %s" % (c, str(classes))
            return classes

        def with_permission(p):
            """
            Return set of guids which have capability p
            """
            print "permission p = " + p
            sql = """SELECT p.info_log
                     FROM permissions p
                     WHERE p.permission = '%s'""" % p
            cursor = self.db.cursor()
            cursor.execute(sql)
            results = cursor.fetchall()
            classes = set([])
            for result in results:
                classes.add(result[0])
            self.db.commit()
            cursor.close()
            print "with_permission(%s): %s" % (p, str(classes))
            return classes

        have_capabilities = None
        for c in capabilities:
            if not have_capabilities:
                have_capabilities = with_capability(c)
            else:
                have_capabilities &= with_capability(c)
        result = set([])
        if have_capabilities:
            for p in permissions:
                result |= (have_capabilities & with_permission(p))
        return list(result)

    def get_c_and_p(self, info_log):
        sql = """SELECT c.capability
                 FROM capabilities c
                 WHERE c.info_log = '%s'""" % info_log
        cursor = self.db.cursor()
        cursor.execute(sql)
        capabilities = [v[0] for v in cursor.fetchall()]
        sql = """SELECT p.permission
                 FROM permissions p
                 WHERE p.info_log = '%s'""" % info_log
        cursor.execute(sql)
        permissions = [v[0] for v in cursor.fetchall()]
        cursor.close()
        return capabilities, permissions

class DeviceRepository:
    """
    Class which provides access to information about devices
    """
    def __init__(self, bootstrap, input_bootstrap_port, opendht_listen_port):
        dht_node = DhtNode(bootstrap, input_bootstrap_port, opendht_listen_port)
        dht_node.start()

    def get_devices(self, capabilities, permissions, active_since):
        info_logs = class_repository.get(capabilities, permissions)
        result = []
        for log in info_logs:
            print "calling dht_get(" + log + ")"
            unfiltered = self.dht_get(log)
            print "unfiltered = " + str(unfiltered)
            devices = self.filter_non_current(unfiltered, active_since)
            print "devices = " + str(devices)
            for device in devices:
                device["info_log"] = log
            result += devices
        for device in result:
            c, p = class_repository.get_c_and_p(device["info_log"])
            device["capabilities"] = c
            device["permissions"] = p
        return result

    def dht_get(self, info_log):
        r = requests.get("http://localhost:" + str(DHT_PORT) + "/rest/v1/devices/" + info_log)
        if r.status_code == 200:
            result = [{str(k): str(v) for k, v in json.loads(str(e)).items()} for e in r.json()]
            return result
        else:
            return False

    def filter_non_current(self, device_dicts, thresh):
        """
        Creates a list of device dicts which does not have duplicate guids and includes
        only device dicts with the most current active_since value. Also does not include
        device dicts which have an active_since value earlier than threshold
        """
        def str_to_datetime(string_val):
            print "string_val = " + str(string_val)
            return datetime.datetime.strptime(string_val, "%Y-%m-%d %H:%M:%S.%f")

        if type(thresh) != datetime.datetime:
            thresh = str_to_datetime(thresh)
        current = {}
        for device in device_dicts:
            guid = device["guid"]
            active_since = device["datetime"]
            device_time = str_to_datetime(active_since)
            if thresh > device_time:
                continue
            if guid in current:
                current_time = str_to_datetime(current[guid]["datetime"])
                if current_time > device_time:
                    continue
            current[guid] = device
        return list(current.values())

class DhtNode(threading.Thread):
    """
    Manages server's connection to a discovery DHT network
    """
    def __init__(self, bootstrap, input_bootstrap_port, opendht_listen_port):
        threading.Thread.__init__(self)
        self.bootstrap = bootstrap # example: "bootstrap.ring.cx:4222"
        self.input_bootstrap_port = input_bootstrap_port
        self.opendht_listen_port = opendht_listen_port
        
    def run(self):
        # Must make a system call to run dht_service because it requires python3
        print "DhtNode: running with bootstrap = %s, input_bootstrap_port = %s, opendht_listen_port = %s" % \
                (self.bootstrap, self.input_bootstrap_port, self.opendht_listen_port)
        if self.bootstrap != None:
            subprocess.call(["python3", "gdpds/dht_service.py", "-b", self.bootstrap, \
                    "-p", str(self.input_bootstrap_port), "-P", str(self.opendht_listen_port)])
        else:
            subprocess.call(["python3", "gdpds/dht_service.py", "-p", str(self.input_bootstrap_port), 
                    "-P", str(self.opendht_listen_port)])

def main():
    global class_repository, device_repository, log_reader
    b_host = None
    b_port = None

    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-b", "--bootstrap", dest="bootstrap",
                      help="specify bootstrap opendht node to connect to in form ip:port")
    parser.add_option("--input_bootstrap_port", dest="input_bootstrap_port", default="4222",
                      help="specify port for this opendht to listen as a bootstrap node on")
    parser.add_option("--opendht_listen_port", dest="opendht_listen_port", default="7992",
                      help="specify port the opendht service will listen for requests on")
    parser.add_option("--registry_listen_port", dest="registry_listen_port", default="80",
                      help="specify port the registry service listens for requests on")
    parser.add_option("-r", "--router", dest="router",
                      help="use gdp router specified in the form ip:port")
    parser.add_option("-u", "--user", dest="user", default="gdp_discovery",
                      help="specify registry database user")
    parser.add_option("-p", "--passwd", dest="passwd", default="gdp_disc438",
                      help="specify registry database password")
    parser.add_option("-H", "--host", dest="host", default="localhost",
                      help="specify registry database host")
    parser.add_option("-n", "--name", dest="name", default="discovery_registry",
                      help="specify registry database name")
    (options, args) = parser.parse_args()
    if options.router:
        router = options.router.split(":")
        router_host = router[0]
        router_port = int(router[1])
    else:
        router_host = None
        router_port = None
    log_reader = info_log_reader.InfoLogReader(router_host, router_port)

    class_repository = DeviceClassRepository(options.user, options.passwd, \
            options.host, options.name)
    device_repository = DeviceRepository(options.bootstrap, options.input_bootstrap_port,
            options.opendht_listen_port)
    app.run(host="0.0.0.0", debug=False, use_reloader=False, port=options.registry_listen_port)
    
if __name__ == '__main__':
    main()
