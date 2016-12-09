#!/usr/bin/env python

import sys
sys.path.append("../") # to import gdpds
import os
import gdpds
import multiprocessing
import paho.mqtt.client as mqtt
import datetime
import threading
import time

MQTT_SERVER = "uhkbbb001.eecs.berkeley.edu"
TIMEOUT = 70 # If no update from device for TIMEOUT seconds, terminate advertisement
TIMEOUT_FREQ = 5 # How often we check for timeouts

REGISTERED_TOPICS = ['device/PowerBlade/c098e5700088', 'device/PowerBlade/c098e570008e', 'device/BLEES/c098e530005c', 'device/BLEES/c098e530005f', 'device/BLEES/c098e5300075', 'device/BLEES/c098e530007b', 'device/PowerBlade/c098e570008b', 'device/BLEES/c098e5300074', 'device/PowerBlade/c098e570008d', 'device/BLEES/c098e5300003', 'device/BLEES/c098e530007a', 'device/BLEES/c098e5300077', 'device/BLEES/c098e5300078', 'device/Blink/c098e590000a']
POWERBLADE_IL = "edu.berkeley.eecs.jordan.nov14.pwrbld_il1"
BLEES_IL = "edu.berkeley.eecs.jordan.nov14.blees_il1"
BLINK_IL = "edu.berkeley.eecs.jordan.nov14.blink_il1"

guid_times = {} # Stores mapping of guid:datetime for last update from device
guid_pids = {} # Stores mapping of guid:pid for advertising clients
lock = threading.Lock()

class MqttListener(threading.Thread):
    def __init__(self, mqtt_server):
        self.mqtt_server = mqtt_server
        threading.Thread.__init__(self)

    def append_zeros(self, string, desired_length):
        zeros = ""
        for i in range(desired_length - len(string)):
            zeros += "0"
        return string + zeros

    def get_info_log(self, guid):
        if "PowerBlade" in guid:
            return POWERBLADE_IL
        if "BLEES" in guid:
            return BLEES_IL
        if "Blink" in guid:
            return BLINK_IL

    def get_output_log(self, topic):
        log_name = "edu.berkeley.eecs.swarmlab.device."
        mac_address = topic.split("/")[2]
        return "edu.berkeley.eecs.swarmlab.device." + mac_address
        
    def gdpds_advertise(self, guid, topic):
        info_log = self.get_info_log(guid)
        output_log = self.get_output_log(topic)
        gdpds.client.advertise(guid=guid, info_log=info_log, output_log=output_log)

    def on_connect(self, client, userdata, flags, rc):
        client.subscribe([(topic, 0) for topic in REGISTERED_TOPICS])
        print "registered for topics: \n" + str(REGISTERED_TOPICS)

    def on_message(self, client, userdata, msg):
        global guid_times, guid_pids, lock
        guid = self.append_zeros(msg.topic, 32)
        lock.acquire()
        if guid not in guid_pids:
            p = multiprocessing.Process(target=self.gdpds_advertise, args=(guid, msg.topic))
            p.start()
            print "thread for " + guid + " started"
            guid_pids[guid] = p
        guid_times[guid] = datetime.datetime.now()
        lock.release()

    def run(self):
        client = mqtt.Client()
        client.on_connect = self.on_connect
        client.on_message = self.on_message
        client.connect(self.mqtt_server)
        client.loop_forever()

def check_timeouts():
    global guid_times, guid_pids, lock
    while True:
        time.sleep(TIMEOUT_FREQ)
        for guid, last_time in guid_times.items():
            if (datetime.datetime.now() - last_time).seconds > TIMEOUT:
                print "terminating thread for " + guid
                lock.acquire()
                guid_pids[guid].terminate()
                del guid_times[guid]
                del guid_pids[guid]
                lock.release()

if __name__=="__main__":
    mqtt_listener = MqttListener(MQTT_SERVER)
    mqtt_listener.daemon = True
    mqtt_listener.start()
    check_timeouts()
