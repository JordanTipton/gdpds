#!/usr/bin/env python

import opendht as dht
import argparse
import json
from optparse import OptionParser
from flask import Flask, request
from flask_restful import Resource, Api

DEFAULT_OPENDHT_PORT = 4225
node = dht.DhtRunner()
app = Flask(__name__)
api = Api(app)

class Device(Resource):
    def get(self, log_name):
        return [v.data.decode("utf-8") for v in node.get(dht.InfoHash.get(log_name))]

    def put(self, log_name):
        guid = json.loads(json.dumps(request.form))["guid"]
        data = bytes(json.dumps(request.form), "utf-8")
        values = node.get(dht.InfoHash.get(log_name))
        value = None
        for val in values:
            if eval(val.data.decode("ascii"))["guid"] == guid:
                value = val
                break
        if value != None:
            # Update existing value if this guid already exists in the dht
            value.data = data
            node.put(dht.InfoHash.get(log_name), value)
        else:
            # Create a new value for this guid if it does not exist in the dht
            node.put(dht.InfoHash.get(log_name), dht.Value(data))
        return [v.data.decode("utf-8") for v in node.get(dht.InfoHash.get(log_name))]

api.add_resource(Device, "/devices/<string:log_name>")

def main():
    global node
    b_host = None
    b_port = None

    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-p", "--port", dest="port",
                      help="specify port for this opendht node to listen on")
    parser.add_option("-b", "--bootstrap", dest="bootstrap",
                      help="specify bootstrap opendht node to connect to in form ip:port")
    (options, args) = parser.parse_args()
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
