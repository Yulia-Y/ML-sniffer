
import asyncio
from datetime import datetime
from scapy.all import TCP, UDP, Ether, IP, sniff
import pyshark
import Connection 
import TcpReconstruction
import psutil
import sys
import signal
import csv
import argparse


# Устанавливаем кодировку консоли на UTF-8
sys.stdout.reconfigure(encoding='utf-8')

# Read configuration from App.config

pcap_name = ('C:\\sniffer\\pcap\\test1.pcap')
session_dir = ('C:\\sniffer\\sessions\\')
dataset_name = ('C:\sniffer\dataset\packets_train.csv')
dataset_minified_name = ('C:\sniffer\dataset\packets_train_minified.csv')

# Создаем парсер аргументов
# parser = argparse.ArgumentParser(description='Пример программы с несколькими флагами')
parser = argparse.ArgumentParser()

# Добавляем флаги
parser.add_argument('-f', '--flag', action='store_true', help='Пример первого флага')
parser.add_argument('-n', '--number', type=int, help='Пример второго флага')

# Парсим аргументы
args = parser.parse_args()

# Used to stop the capture loop
global stop_capturing
stop_capturing = False

start_time = datetime.now()
connections = {}

# Results
csv_list = []
csv_minified = []


startTime = datetime.now()

# Print version
ver = "ML-IDS Sniffer using SharpPcap"
print(ver)

def write_csv():
        with open(dataset_name, "w") as sw:
            print(dataset_name)
            csv_writer = csv.writer(sw)
            csv_writer.writerow([
            "Flow Key,",  # 1, A
            "Source IP,",  # 2, B
            "Source Port,",  # 3, C
            "Destination IP,",  # 4, D
            "Destination Port,",  # 5, E
            "Protocol,",  # protocol = TCP 6, F
            "Timestamp,",  # 7, G
            "Flow Duration,",  # 8, H
            "Total Packets,",
            "Total Fwd Packets,",  # 9, I
            "Total Backward Packets,",  # 10, J
            "Total Length of Fwd Packets,",  # 11, K
            "Total Length of Bwd Packets,",  # 12, L
            "Fwd Packet Length Max,",  # 13, M
            "Fwd Packet Length Min,",  # 14, N
            "Fwd Packet Length Mean,",  # 15, O
            "Fwd Packet Length Std,",  # 16, P
            "Bwd Packet Length Max,",  # 17, Q
            "Bwd Packet Length Min,",  # 18, R
            "Bwd Packet Length Mean,",  # 19, S
            "Bwd Packet Length Std,",  # 20, T
            "Flow Bytes/s,",  # 21, U
            "Flow MB/s,",
            "Flow Packets/s,",  # 22, V
            "Flow IAT Mean,",  # 23, W
            "Flow IAT Std,",  # 24, X
            "Flow IAT Max,",  # 25, Y
            "Flow IAT Min,",  # 26, Z
            "Fwd IAT Total,",  # 27, AA
            "Fwd IAT Mean,",  # 28, AB
            "Fwd IAT Std,",  # 29, AC
            "Fwd IAT Max,",  # 30, AD
            "Fwd IAT Min,",  # 31, AE
            "Bwd IAT Total,",  # 32, AF
            "Bwd IAT Mean,",  # 33, AG
            "Bwd IAT Std,",  # 34, AH
            "Bwd IAT Max,",  # 35, AI
            "Bwd IAT Min,",  # 36, AJ
            # 37, AK, Fwd PSH Flags
            # 38, AL, Bwd PSH Flags
            # 39, AM, Fwd URG Flags
            # 40, AN, Bwd URG Flags
            "Fwd Header Length,",  # 41, AO
            "Bwd Header Length,",  # 42, AP
            "Fwd Packets/s,",  # 43, AQ
            "Bwd Packets/s,",  # 44, AR
            "Min Packet Length,",  # 44, AS
            "Max Packet Length,",  # 45, AT
            "Packet Length Mean,",  # 46, AU
            "Packet Length Std,",  # 47, AV
            "Packet Length Variance,",  # 48, AW
            # 49, AX, FIN Flag Count
            # 50, AY, SYN Flag Count
            # 51, AZ, RST Flag Count
            # 52, BA, PSH Flag Count
            # 53, BB, ACK Flag Count
            # 54, BC, URG Flag Count
            # 55, BD, CWE Flag Count
            # 56, BE, ECE Flag Count
            # 57, BF, Down/Up Ratio
            "Average Packet Size,",  # 58, BG
            "Average Fwd Segment Size,",  # 59, BH
            "Average Bwd Segment Size,",  # 60, BH
            "Packet Length List",  # 60, BH
            "Label\n"
            ])

            for line in csv_list:
                csv_writer.writerow([line])
            # sw.write(csv_list)

        with open(dataset_minified_name, "w") as sw:
            csv_writer = csv.writer(sw)
            csv_writer.writerow([
                "Flow Key,",
                "Flow Bytes/s,", 
                "Average Packet Size,",
                "Max Packet Length,",
                "Packet Length Mean,",
                "Fwd Packet Length Mean,",
                "Fwd IAT Min,",
                "Total Length of Fwd Packets,",
                "Avg Fwd Segment Size,",
                "Flow IAT Mean,",
                "Fwd Packet Length Max",  # 60, BH
                "Label\n"]
            )
            for line in csv_minified:
                csv_writer.writerow([line])
            # sw.write(csv_minified)

def output_finished_session(c, tr):
    # Write data to CSV and close TcpReconstruction objects

    tr.calculate_statistics()
    newLine = (
        f"{(c)},"
        f"{c.source_ip},"
        f"{c.source_port},"
        f"{c.destination_ip},"
        f"{c.destination_port},"
        f"6,"
        f"{tr.get_timestamp_string()},"
        #f"{(datetime.fromtimestamp(tr.duration)).total_seconds() * 1000},"
        f"{tr.duration},"
        f"{tr.total_packets},"
        f"{tr.total_fwd_packets},"
        f"{tr.total_bwd_packets},"
        f"{tr.total_length_of_fwd_packets},"
        f"{tr.total_length_of_bwd_packets},"
        f"{tr.fwd_packet_length_max},"
        f"{tr.fwd_packet_length_min},"
        f"{tr.fwd_packet_length_mean:.5f},"
        f"{tr.fwd_packet_length_std:.5f},"
        f"{tr.bwd_packet_length_max},"
        f"{tr.bwd_packet_length_min},"
        f"{tr.bwd_packet_length_mean:.5f},"
        f"{tr.bwd_packet_length_std:.5f},"
        f"{tr.get_flow_bytes_per_second():.5f},"
        f"{tr.get_flow_bytes_per_second() / 1000000:.5f},"
        f"{tr.get_packets_per_second():.5f},"
        f"{tr.flow_iat_mean:.5f},"
        f"{tr.flow_iat_std:.5f},"
        f"{tr.flow_iat_max:.5f},"
        f"{tr.flow_iat_min:.5f},"
        f"{tr.fwd_iat_total:.5f},"
        f"{tr.fwd_iat_mean:.5f},"
        f"{tr.fwd_iat_std:.5f},"
        f"{tr.fwd_iat_max:.5f},"
        f"{tr.fwd_iat_min:.5f},"
        f"{tr.bwd_iat_total:.5f},"
        f"{tr.bwd_iat_mean:.5f},"
        f"{tr.bwd_iat_std:.5f},"
        f"{tr.bwd_iat_max:.5f},"
        f"{tr.bwd_iat_min:.5f},"
        f"{tr.fwd_header_length},"
        f"{tr.bwd_header_length},"
        f"{tr.get_fwd_packets_per_second():.5f},"
        f"{tr.get_bwd_packets_per_second():.5f},"
        f"{tr.min_packet_length},"
        f"{tr.max_packet_length},"
        f"{tr.packet_length_mean:.5f},"
        f"{tr.packet_length_std:.5f},"
        f"{tr.packet_length_variance:.5f},"
        f"{tr.average_packet_size:.5f},"
        f"{tr.average_fwd_segment_size:.5f},"
        f"{tr.average_bwd_segment_size:.5f},"
        f"{tr.subflow_count},"
        f"{int(0)}"
    )
    csv_list.append(newLine)

    newLineMinified = (
        f"{c},"
        f"{tr.get_flow_bytes_per_second():.5f},"
        f"{tr.average_packet_size:.5f},"
        f"{tr.max_packet_length},"
        f"{tr.packet_length_mean:.5f},"
        f"{tr.fwd_packet_length_mean:.5f},"
        f"{tr.flow_iat_min:.5f},"
        f"{tr.total_length_of_fwd_packets},"
        f"{tr.average_fwd_segment_size:.5f},"
        f"{tr.flow_iat_mean:.5f},"
        f"{tr.fwd_packet_length_max},"
        f"{int(0)}"
    )
    csv_minified.append(newLineMinified)

    tr.close()


def handle_cancel_key_press(sender, e):
    print("-- Stopping capture")

    finishTime = datetime.now()
    totalTime = finishTime - startTime

    print(f"\nTotal reconstruct time: {totalTime.total_seconds()} seconds")


    # Tell the handler that we are taking care of shutting down, don't
    # shut us down after we return because we need to do just a little
    # bit more processing to close the open capture device etc
    # try:
    #     if not offlinePcap:
    #         print(device.statistics())
    # except Exception as ex:
    #     print(str(ex))

    # Close the pcap device
    # device.close()

    # Complete all sessions
    for key, value in connections.items():
        output_finished_session(key, value)
    connections.clear()

    write_csv()
    sys.exit(0)

def packet_callback(packet):
    # В этой функции можно обрабатывать каждый перехваченный пакет
    print(packet)




# Retrieve the device list
devices = psutil.net_if_addrs()


# If no devices were found print an error
if len(devices) < 1:
    print("No devices were found on this machine")
    exit()

print()
print("The following devices are available on this machine:")
print("----------------------------------------------------")
print()

# Print out the devices
# for i, dev in enumerate(devices):
#     print(f"{i}) {dev['name']} {dev['description']}")
for i, dev in enumerate(devices):
    print(f"{i}) {dev}")


# print(capture_dev)

print(f"{len(devices)}) Read packets from offline pcap file")

# Choose a device to capture
choice = int(input("-- Please choose a device to capture: "))
# choice = 0
interface_names = list(devices.keys())
device = None
offlinePcap = False
signal.signal(signal.SIGINT, handle_cancel_key_press)
# if choice == len(devices):
#     capFile = input(f"-- Please enter an input capture file name [test1.pcap]: ")
#     if len(capFile) < 2:
#         capFile = "test1.pcap"
#     device = pyshark.FileCapture(capFile)
#     offlinePcap = True
# else:

# print(device)
# device.apply_on_packets(packet_callback)
# async def capture_and_filter():
#     if device is None:
#         print("Ошибка: объект device не был корректно инициализирован")
#         return
#     read_timeout = 1  # Время ожидания в секундах
#     async with device:
#         if device is not None:
#             await device.set_debug()
#             await device.sniff(timeout=read_timeout)  # Начинаем захват
#             await asyncio.gather(
#                 device.apply_on_packets(lambda pkt: "tcp" in pkt, timeout=read_timeout)
#             )

# asyncio.run(capture_and_filter())

##print("1")
# Open the device for capturing

# device = pyshark.LiveCapture(interface=interface_names[choice])
# ///////
# readTimeoutMilliseconds = 1000
# if offlinePcap:
#     pass  # No need to open the file capture device in pyshark
# else:
#     device.sniff(timeout=readTimeoutMilliseconds / 1000)
# ////////

# Set filter
# //////
    
# filter = "tcp"
# print("4")
# device.apply_on_packets(lambda pkt: filter in pkt, timeout=readTimeoutMilliseconds / 1000)
# print("5")
# ////////
# def packet_handler(packet):
#     if TCP in packet:
#         # Ваша логика обработки TCP пакетов здесь
#         print(packet.summary())  # Пример вывода информации о пакете


print()
print(f"-- The following tcpdump filter will be applied: tcp")
print()
# print(f"-- Listening on {device.output_if_listening()}, hit 'ctrl-c' to stop...")




counter = 0
while not stop_capturing:
# while counter < 10:
    counter += 1
    # if counter > 6000:
    #     continue

    # try:
    #     rawCapture = next(device.sniff_continuously())
    # except StopIteration:
    #     continue

    # if rawCapture is None:
    #     continue

    # Use PacketDotNet to parse this packet and print out its high level information
    def packet_handler(p):
        # if p:
        #     return

        if p.getlayer(TCP):
            
            packet = Ether(p)
            if p.haslayer(IP):
                
                ip_packet = p.getlayer(IP)

                # Create a key for the dictionary
                c = Connection.Connection(ip_packet.src, ip_packet.sport, ip_packet.dst, ip_packet.dport)
                

                # Create a new entry if the key does not exist
                if c not in connections:
                    fileName = c.get_filename(session_dir)
                    tcpReconstruction = TcpReconstruction.TcpReconstruction()
                    # tcpReconstruction.tcp_reconstruction(f"{fileName}\\file_{counter}")
                    tcpReconstruction.tcp_reconstruction(fileName)
                    connections[c] = tcpReconstruction
                    print(c)
            
                # Use the TcpReconstruction class to reconstruct the session
                connections[c].reassemble_packet(p, p.time)

                # Do like CICFlowMeter
                tcp = p.getlayer(TCP)
                if tcp is not None and connections[c].fin_flag_count == 2 and connections[c].total_packets > 1:
                    ethP = p.getlayer(Ether)

                    output_finished_session(c, connections[c])
                    connections.pop(c)

                if isinstance(packet, Ether):
                    messageToConsole = ""
                    protocol = ""

                    eth = packet
                    ip = p.getlayer(IP)
                    if ip:
                        tcp = p.getlayer(TCP)
                        if tcp:
                            messageToConsole += f"TCP packet: {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} {protocol} {ip.len}"

                            newLine = f"{datetime.now().strftime('%Y-%m-%d')},{datetime.now().strftime('%H-%M-%S-%f')},{eth.src},{eth.dst},{ip.src},{tcp.sport},{ip.dst},{tcp.dport},{ip.len},{bool(tcp.flags & 0x02)},{bool(tcp.flags & 0x01)},{bool(tcp.flags & 0x10)},{tcp.window},{tcp.ack},{tcp.seq},{ip.ttl}"
                            csv_list.AppendLine(newLine)

                        udp = p.getlayer(UDP)
                        if udp:
                            messageToConsole += f"UDP packet: {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport} {ip.len}"

                            # Manipulate UDP parameters
                            # udp.sport = 9999
                            # udp.dport = 8888

                    # if ip:
                    #     if ip.src == '1.2.3.4' or ip.dst == '1.2.3.4':
                    #         ip.src = '4.3.2.1'
                    #         ip.dst = '4.4.4.4'

                    # if eth:
                    #     if eth.src == '00:11:22:33:44:55' or eth.dst == '00:11:22:33:44:55':
                    #         eth.src = '00:00:00:00:00:00'
                    #         eth.dst = '99:88:77:66:55:00'

                    # if tcp:
                    #     if tcp.sport == 22 or tcp.dport == 22:
                    #         protocol = "SSH"
                    #     if tcp.sport == 3389 or tcp.dport == 3389:
                    #         protocol = "RDP"

                    #     # Manipulate TCP parameters
                    #     # tcp.sport = 9999
                    #     # tcp.dport = 8888
                    #     # tcp.flags.syn = not tcp.flags.syn
                    #     # tcp.flags.fin = not tcp.flags.fin
                    #     # tcp.flags.ack = not tcp.flags.ack
                    #     # tcp.window = 500
                    #     # tcp.ack = 800
                    #     # tcp.seq = 800
                    
                    print(messageToConsole)
    sniff(iface=interface_names[choice], prn=packet_handler, filter="tcp")


