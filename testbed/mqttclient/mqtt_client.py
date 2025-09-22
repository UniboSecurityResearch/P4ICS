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

send_times = {}

# Result file
output_file = open("publish_times.txt", "w")

def on_connect(client, userdata, flags, reason_code):
    print(instance_number, f"Connected with result code {reason_code}")
    client.subscribe("encyclopedia/#", qos=1)
    lock.release()

def on_message(client, userdata, msg):
    print(instance_number, datetime.datetime.now().strftime("%H:%M:%S"),
          msg.topic+" "+str(msg.payload))

def on_publish(client, userdata, mid):
    # Calculate delay
    if mid in send_times:
        delay = time.time() - send_times[mid]
        output_file.write(f"{delay:.6f}\n")
        output_file.flush()
        del send_times[mid]

mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1,
                    client_id="", userdata=None, protocol=mqtt.MQTTv311)
mqttc.on_connect = on_connect
mqttc.on_message = on_message
mqttc.on_publish = on_publish

mqttc.connect("200.1.1.8", 1883)
mqttc.socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

mqttc.loop_start()

lock.acquire()

pid = os.getpid()

for i in range(100000):
    payload = f"hot/{instance_number}@{datetime.datetime.now().strftime('%H:%M:%S')}"
    info = mqttc.publish("encyclopedia/temperature", payload=payload, qos=1)
    send_times[info.mid] = time.time()  # save send time
    # optional: slow down slightly to avoid saturating
    time.sleep(0.001)

print(instance_number, "END")

# Wait for all messages to be confirmed
while send_times:
    time.sleep(0.1)

mqttc.loop_stop()
output_file.close()

print(instance_number, "LOOP-STOP")
