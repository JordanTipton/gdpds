#!/usr/bin/env python

import opendht as dht
import argparse
import json
from optparse import OptionParser
from flask import Flask, request
from flask_restful import Resource, Api

node = dht.DhtRunner()
app = Flask(__name__)
api = Api(app)

class Device(Resource):
    def get(self, log_name):
        return [v.data.decode("utf-8") for v in node.get(dht.InfoHash.get(log_name))]

    def put(self, log_name):
        print("dht_service - put: log_name = " + log_name)
        guid = request.form["guid"]
        print("dht_service - put: guid = " + guid)
        data = bytes(json.dumps(request.form).replace("\x00", "").replace("\\u0000", ""), "utf-8")
        print("dht_service - put: creating new with data = " + str(data))
        node.put(dht.InfoHash.get(log_name), dht.Value(data))
        print("dht_service - put: 5")
        result = [v.data.decode("utf-8") for v in node.get(dht.InfoHash.get(log_name))]
        print("dht_service - put: result = " + str(result))
        return result

api.add_resource(Device, "/rest/v1/devices/<string:log_name>")

def main():
    global node
    b_host = None
    b_port = None

    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-p", "--port", dest="port", default="4222",
                      help="specify port for this opendht node to listen as a bootstrap node on")
    parser.add_option("-P", "--opendht_listen_port", dest="opendht_listen_port", default="5000",
                      help="specify port for to listen for restful requests on")
    parser.add_option("-b", "--bootstrap", dest="bootstrap",
                      help="specify bootstrap opendht node to connect to in form ip:port")
    (options, args) = parser.parse_args()
    print("dht_service: port=%s, listen_port=%s, bootstrap=%s" % \
            (options.port, options.opendht_listen_port, options.bootstrap))

    if options.bootstrap:
        b_host, b_port = options.bootstrap.split(":")
    id = dht.Identity()
    id.generate()
    node.run(id, port=int(options.port))
    if b_host:
        # connect node to existing opendht network using given bootstrap node
        print("dht_service: b_host = %s, b_port = %s" % (b_host, b_port))
        node.bootstrap(b_host, b_port)
    print("running with port = " + options.opendht_listen_port)
    app.run(debug=False, use_reloader=False, port=int(options.opendht_listen_port))
    
if __name__ == '__main__':
    main()
