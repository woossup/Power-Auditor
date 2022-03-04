#!/usr/bin/env python
import signal
import logging
import sys
import time
import socket
import threading
import getopt
import queue
import uuid
import RPi.GPIO as GPIO
from ina219 import INA219
from ina219 import DeviceRangeError

# Global Variables
SHUNT_OHMS = 0.07
MAX_EXPECTED_AMPS = 1.5
DATA_FILE = 'power.csv'
SERVER_IP = '10.0.1.16'
SERVER_PORT = 10000
SAMPLING_RATE = 1700
SLIDING_WINDOW_LEN = 1500
OVERLAPPING_RATIO = 3

sensing_queue = queue.Queue()
data_file = open(DATA_FILE, "w")
sensor = INA219(SHUNT_OHMS, MAX_EXPECTED_AMPS, log_level=logging.INFO)

GPIO.setmode(GPIO.BCM)
GPIO.setup(24, GPIO.OUT)

# Interrupt Handler
def signal_handler(signal, frame):
    close()

# Initialize Smart-plug
def init():
    global sampling_rate
    global packet_len 
    global hostname
    global tcp_socket
    global server_address
    global connected

    # Global Variables
    sampling_rate = int(SAMPLING_RATE/sampling_mod)
    packet_len = int(sampling_rate*SLIDING_WINDOW_LEN/1000/OVERLAPPING_RATIO)
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostname = socket.gethostname()
    server_address = (SERVER_IP, SERVER_PORT)
    connected = False

    # Interrupt Handler
    signal.signal(signal.SIGINT, signal_handler)

    # Current Sensor
    sensor.configure(sensor.RANGE_16V,sensor.GAIN_4_160MV,sensor.ADC_11BIT,sensor.ADC_11BIT)

    # TCP Socket Client
    if networking == True:
        connect()

# Connect to Unit-B (Server)
def connect():
    global connected
    global tcp_socket

    while True:
        try:
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print('%% Connecting to Unit-B (%s:%s)' % server_address)
            tcp_socket.connect(server_address)
            connected = True
            break
        except (OSError,ConnectionRefusedError) as e:
            print(e)
            time.sleep(10)
            continue

# Close Smart-plug
def close():
    if networking == True:
        tcp_socket.close()

    data_file.close()

    GPIO.cleanup() # cleanup all GPIO

    sys.exit(0)

# Socket Transmit
def send_to_server(data):
    global connected

    msg_id = uuid.uuid1()
    header = [hostname, str(msg_id)[:16], sampling_rate, SLIDING_WINDOW_LEN,
           OVERLAPPING_RATIO, packet_len]

    # Assemble header and data
    packet = header + data

    # Sending packet to Server
    packet = bytes(str(packet).strip('[]UUID(').replace('\'', '').replace(' ','').replace(')',''), "utf-8")
    if connected == True:
        try:
            tcp_socket.sendall(packet)
            print("%% Data sent! (%d bytes" % len(packet), end = '')
        except (BrokenPipeError, IOError):
            print ('BrokenPipeError caught', file = sys.stderr)
            connected = False
            # Try reconnecting to Unit-B
            reconnector = threading.Thread(target=connect, daemon=True)
            reconnector.start()

# Power Sensing Thread
def loader():
    print ('%% Starting Loader')
    print('   Shunt Ohms -- %s \u03A9' % SHUNT_OHMS)
    print('   File Name -- %s' % DATA_FILE)
    i = 0

    while True:
        try:
            # Read Sensing Data
            sensing_data = sensor.power()
 
            # Adjust Sampling Rate and Queue Data
            if i % sampling_mod == 0:
                sensing_queue.put(sensing_data)
            i = i + 1

        except DeviceRangeError as e:
            print(e)

# Socket Interface Thread
def sender():
    print ('%% Starting Sender')
    print('   Hostname -- %s' % hostname)
    print('   Sampling Rate -- %d Hz' % sampling_rate)
    print('   Sliding Window Size -- %d ' % SLIDING_WINDOW_LEN)
    print('   Overlapping Ratio -- %d ' % OVERLAPPING_RATIO)
    print('   Packet Size -- %d' % packet_len)

    sending_data = []
    init_time = time.time()

    while True:
        try:
            # Get Sensing Data
            queue_data = '{:08.{prec}f}'.format(sensing_queue.get(), prec=3)

            # Store Data in a File
            data_file.write(queue_data + '\n')

            # Send Data to Server
            if networking == True:
                sending_data.append(queue_data)

                if len(sending_data) == packet_len :
                    send_to_server(sending_data)
                    sending_data.clear()

                    if connected == True:
                        sent_time = time.time()
                        elapsed = (sent_time - init_time) * 1000
                        print(", %d ms)" % elapsed)
                        init_time = time.time()

        except IndexError:
            continue

# Message Parser
def parse_message(msg):
    # TODO : Control messages

    #if( len(msg) > 0 ):
    #    print('Shutdown IoT Device')

    print('')

# Socket Interface Thread
def receiver():
    if networking == False:
        return 

    print ('%% Starting Receiver')

    # Receive Socket Data
    while True:
        msg = ''
        while True:
            recv = tcp_socket.recv(64)
            if len(recv) <= 0:
                break       
            msg += recv.decode("utf-8")

            # TODO: Checking message format
            print(msg)
            break

        if len(msg) == 0:
            continue
        print("%% Data received! (%d bytes)" % len(msg))
        parse_message(msg)

# Display Usage
def usage():
    print("usage: python3 smart-plug.py [--mode=<mode>] [--sampling_mod=<modulus>] [--help]\n")
    print("\t-m, --mode[=<mode>]")
    print("\t\t\t\t file : file-only mode, networking disabled (default)")
    print("\t\t\t\t all : both file and networking enabled")
    print("\t-s, --sampling_mod[=<modulus>]")
    print("\t\t\t\t 1 : Sampling Rate 1.7KHz (default)")
    print("\t\t\t\t 2 : Sampling Rate 850Hz")
    print("\t\t\t\t 3 : Sampling Rate 566Hz")
    print("\t\t\t\t 4 : Sampling Rate 438Hz")
    print("\t-h, --help\t\tDisplay help information\n")

# Manage Options
def options():
    global mode 
    global networking
    global sampling_mod 

    # Default Mode
    mode = "file"
    networking = False
    sampling_mod = 1

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hm:s:", ["help", "mode=", "sampling_mod="])
    except getopt.GetoptError:
        # print help information and exit:
        usage()
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        if o in ("-m", "--mode"):
            mode = a
        if o in ("-s", "--sampling_mod"):
            sampling_mod = int(a)

    if mode == "file":
        networking = False
    elif mode == "all":
        networking = True
    else:
        usage()
        sys.exit(2)

    if sampling_mod not in range(1,5):
        usage()
        sys.exit(2)
 
# Main
if __name__ == "__main__":
    # Manage Options
    options()
  
    # Initialize Smart-plug
    init()

    print("%% Starting Smart-plug Service ", end='')
    if networking == False:
        print("(File-Only)")
    else:
        print("(Networking-Enabled)")

    # Power Sensing Thread
    loader = threading.Thread(target=loader, daemon=True)
    loader.start()

    # Socket Interface Threads
    sender = threading.Thread(target=sender, daemon=True)
    sender.start()

    receiver = threading.Thread(target=receiver, daemon=True)
    receiver.start()

    #GPIO.output(24, GPIO.HIGH)
    #time.sleep(10)
    #GPIO.output(24, GPIO.LOW)

    loader.join()
    sender.join()
    receiver.join()   
    reconnector.join()
