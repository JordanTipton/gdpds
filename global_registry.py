#!/usr/bin/env python

import opendht as dht
import argparse
import json
import gdp
import MySQLdb
from optparse import OptionParser
from flask import Flask, request
from flask_restful import Resource, Api
import info_log_reader
import datetime

DEFAULT_OPENDHT_PORT = 4226
node = dht.DhtRunner()
app = Flask(__name__)
api = Api(app)
log_reader = None
class_repository = None

class Device(Resource):
	def get(self):
		capabilities = request.args.getlist("capability")
		permissions = request.args.getlist("permissions")
        active_since = request.args.get("active_since")
		return DeviceRepository.get(capabilities, permissions, active_since)

class DeviceClass(Resource):
	def put(self):
		form_data = json.loads(json.dumps(request.form))
		info_log = form_data["info_log"]
		capabilities, permissions = log_reader.read(info_log)[:2]
		class_repository.store_new(guid, info_log, capabilities, permissions)
		return class_repository.get(capabilities, permissions)

api.add_resource(Device, "/devices")
api.add_resource(DeviceClass, "/deviceclasses")

class DeviceClassRepository:
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
            db.commit()
        except MySQLdb.Error, e:
            print "Error %d: %s" % (e.args[0], e.args[1])
            #sys.exit(1)

    def store_new(self, info_log, capabilities, permissions):
        try:
            cursor = self.db.cursor()
            
            #insert client info into capabilities table
            sql = """INSERT INTO `capabilities`
                     (`capability`, `info_log`)
                     VALUES """
            for capability in capabilities:
                sql += "('" + capability + "', '" + info_log + "'), "
            sql = sql[:-2] + ";"
            cursor.execute(sql)

            #insert client info into permissions table
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
        def with_capability(c):
            """
            Return set of guids wich have capability c
            """
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
            return classes

        def with_permission(p):
            """
            Return set of guids which have capability p
            """
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
        db.close()
        return result

class DeviceRepository:
    @staticmethod
    def get_devices(capabilities, permissions, active_since):
        if type(active_since) == str:
            active_since = datetime.datetime.strptime(active_since, "%Y-%m-%d %H:%M:%S.%f")
        info_logs = class_repository.get(capabilities, permissions)
        result = []
        for log in info_logs:
            devices = [v.data.decode("utf-8") for v in node.get(dht.InfoHash.get(info_log))]
            for device in devices:
                last_active = datetime.datetime.strptime(device["datetime"], "%Y-%m-%d %H:%M:%S.%f")
                if last_active < active_since:
                    devices.remove(device)
                device["info_log"] = log
            result += devices
        return result

def main():
    global node, log_reader
    b_host = None
    b_port = None

    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-p", "--port", dest="port",
                      help="specify port for this opendht node to listen on")
    parser.add_option("-b", "--bootstrap", dest="bootstrap",
                      help="specify bootstrap opendht node to connect to in form ip:port")
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
    if options.port:
        port = int(options.port)
    else:
        port = DEFAULT_OPENDHT_PORT

    if options.bootstrap:
        b_host, b_port = options.bootstrap.split(":")
    id = dht.Identity()
    id.generate()
    node.run(id, port=port)
    if b_host:
        # connect node to existing opendht network using given bootstrap node
        node.bootstrap(b_host, b_port)
    app.run(debug=False, use_reloader=False)
    
if __name__ == '__main__':
    main()