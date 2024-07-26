import datetime
import time
import os
import sys
import socket

import paho.mqtt.client as mqtt
from threading import Lock

lock = Lock()
lock.acquire()

if len(sys.argv) == 2:
	instance_number = sys.argv[1]
else:
	instance_number = ""

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, reason_code, properties):
	print(instance_number, f"Connected with result code {reason_code}")
	# Subscribing in on_connect() means that if we lose the connection and
	# reconnect then subscriptions will be renewed.

	client.subscribe("encyclopedia/#", qos=1)

	lock.release()


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
	print(instance_number, datetime.datetime.now().strftime("%H:%M:%S"), msg.topic+" "+str(msg.payload))


mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="", userdata=None, protocol=mqtt.MQTTv5)
mqttc.on_connect = on_connect
mqttc.on_message = on_message

# mqttc.username_pw_set("username", "password")

# mqttc.connect("localhost", 1883)
mqttc.connect("200.1.1.8", 1883)
mqttc.socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

mqttc.loop_start()

lock.acquire()  # Waits for the connection to establish (and the subscription to take effect) before publishing

pid = os.getpid()

for i in range(10):
	print(instance_number, datetime.datetime.now().strftime("%H:%M:%S"), "Sending message")
	mqttc.publish("encyclopedia/temperature", payload="hot/" + str(instance_number) + "@" + datetime.datetime.now().strftime("%H:%M:%S"), qos=1)
	print(instance_number, datetime.datetime.now().strftime("%H:%M:%S"), "Message sent")
	time.sleep(0.5)

print(instance_number, "END")

mqttc.loop_stop()

print(instance_number, "LOOP-STOP")

