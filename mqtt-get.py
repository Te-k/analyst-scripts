#!/usr/bin/env python3
import paho.mqtt.client as mqtt
import argparse


def on_connect(client, userdata, flags, rc):
    print("[+] Connection successful")
    client.subscribe('#', qos = 1)        # Subscribe to all topics
    client.subscribe('$SYS/#')            # Broker Status (Mosquitto)

def on_message(client, userdata, msg):
    print('[+] Topic: %s - Message: %s' % (msg.topic, msg.payload))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Try to subscribe to some MQTT servers')
    parser.add_argument('--port', '-p', type=int, default=1883, help="port")
    parser.add_argument('SERVER', help="Server IP address")
    args = parser.parse_args()

    client = mqtt.Client(client_id = "MqttClient")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(args.SERVER, args.port, 60)
    client.loop_forever()
