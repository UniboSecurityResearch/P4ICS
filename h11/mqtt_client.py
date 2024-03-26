import datetime
import time

import paho.mqtt.client as mqtt
from threading import Lock

lock = Lock()
lock.acquire()

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, reason_code, properties):
	print(f"Connected with result code {reason_code}")
	# Subscribing in on_connect() means that if we lose the connection and
	# reconnect then subscriptions will be renewed.

	client.subscribe("encyclopedia/#", qos=1)

	lock.release()


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
	print(datetime.datetime.now().strftime("%H:%M:%S"), msg.topic+" "+str(msg.payload))


mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="", userdata=None, protocol=mqtt.MQTTv5)
mqttc.on_connect = on_connect
mqttc.on_message = on_message

# mqttc.username_pw_set("username", "password")

mqttc.connect("200.1.1.8", 1883)

mqttc.loop_start()

lock.acquire()  # Waits for the connection to establish (and the subscription to take effect) before publishing

for i in range(10):
	print(datetime.datetime.now().strftime("%H:%M:%S"), "Sending message")
	mqttc.publish("encyclopedia/temperature", payload="hot@" + datetime.datetime.now().strftime("%H:%M:%S"), qos=1)
	print(datetime.datetime.now().strftime("%H:%M:%S"), "Message sent")
	time.sleep(10)

mqttc.loop_stop()



