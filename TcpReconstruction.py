from math import isclose, isinf
from datetime import datetime, timedelta
from typing import List, Union
from math import sqrt
from scapy.all import IP, TCP
import socket
import statistics

# https://www.codeproject.com/Articles/20501/TCP-Session-Reconstruction-Tool

# Translated from the file follow.c from WireShark source code
# the code can be found at: http://www.wireshark.org/download.html
# follow.c => Copyright 1998 Mike Hall<mlh@io.com>

# Here we are going to try and reconstruct the data portion of a TCP
# session. We will try and handle duplicates, TCP fragments, and out
# of order packets in a smart way.

class TcpFragment:
    def __init__(self):
        self.seq = 0
        self.len = 0
        self.dataLength = 0
        self.data = None
        self.next = None

class TcpReconstruction:
    def __init__(self):
        # Holds two linked list of the session data, one for each direction
        self.frags = [None, None]
        # Holds the last sequence number for each direction
        self.sequenceNumber = [0, 0]
        self.source_address = [0, 0]
        self.source_port = [0, 0]
        self.empty_tcp_stream = True
        self.tcp_port = [0, 0]
        self.bytes_written = [0, 0]
        self.file_stream = None
        self.incomplete_tcp_stream = False
        self.closed = False

        # 7, G
        self.flow_start_time = None
        self.fwd_start_time = None
        self.bwd_start_time = None
        self.flow_last_seen = None
        self.fwd_last_seen = None
        self.bwd_last_seen = None
        # 8, H
        self.duration = None

        self.packet_size_list = []
        self.packet_size_fwd_list = []
        self.packet_size_bwd_list = []
        self.flow_iat_list = []
        self.fwd_iat_list = []
        self.bwd_iat_list = []

        # [Kahram 2018, Appendix A]
        self.total_packets = 0
        # 9, I
        self.total_fwd_packets = 0
        # 10, J
        self.total_bwd_packets = 0
        # 11, K
        self.total_length_of_fwd_packets = 0
        # 12, L
        self.total_length_of_bwd_packets = 0
        # 13, M
        self.fwd_packet_length_max = 0
        # 14, N
        self.fwd_packet_length_min = 0
        # 15, O
        self.fwd_packet_length_mean = 0
        # 16, P
        self.fwd_packet_length_std = 0
        # 17, Q
        self.bwd_packet_length_max = 0
        # 18, R
        self.bwd_packet_length_min = 0
        # 19, S
        self.bwd_packet_length_mean = 0
        # 20, T
        self.bwd_packet_length_std = 0

        # IAT = inter-arrival time, research application error [Kahram2018]
        # 23, W
        self.flow_iat_mean = 0
        # 24, X
        self.flow_iat_std = 0
        # 25, Y
        self.flow_iat_max = 0
        # 26, Z
        self.flow_iat_min = 0
        # 27, AA
        self.fwd_iat_total = 0
        # 28, AB
        self.fwd_iat_mean = 0
        # 29, AC
        self.fwd_iat_std = 0
        # 30, AD
        self.fwd_iat_max = 0
        # 31, AE
        self.fwd_iat_min = 0
        # 32, AF
        self.bwd_iat_total = 0
        # 33, AG
        self.bwd_iat_mean = 0
        # 34, AH
        self.bwd_iat_std = 0
        # 35, AI
        self.bwd_iat_max = 0
        # 36, AJ
        self.bwd_iat_min = 0

        # 37, AK, Fwd PSH Flags
        # 38, AL, Bwd PSH Flags
        # 39, AM, Fwd URG Flags
        # 40, AN, Bwd URG Flags

        # 41, AO
        self.fwd_header_length = 0
        # 42, AP
        self.bwd_header_length = 0
        # GetFwdPacketsPerSecond() # 43, AQ
        # GetBwdPacketsPerSecond() # 44, AR

        # 44, AS
        self.min_packet_length = 0
        # 45, AT
        self.max_packet_length = 0
        # 46, AU
        self.packet_length_mean = 0
        # 47, AV
        self.packet_length_std = 0
        # 48, AW
        self.packet_length_variance = 0

        # 49, AX, FIN Flag Count
        self.fin_flag_count = 0
        # 58, BG
        self.average_packet_size = 0
        # 59, BH
        self.average_fwd_segment_size = 0
        # 60, BH
        self.average_bwd_segment_size = 0

        self.subflow_count = -1
        self.subflow_start_time_ts = 0
        self.subflow_last_seen_ts = 0


    def calculate_statistics(self):
        # http://www.netflowmeter.ca/netflowmeter.html
        # https://github.com/ISCX/CICFlowMeter/blob/1d4e34eee43fd2e5fc37bf37dbae0558ca7c17fe/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java
        # 
        # dumpFlowBasedFeatures()

        self.duration = (datetime.fromtimestamp(self.flow_last_seen) - datetime.fromtimestamp(self.flow_start_time)).total_seconds()

        self.packet_size_list = self.packet_size_fwd_list + self.packet_size_bwd_list

        if self.packet_size_fwd_list:
            self.fwd_packet_length_max = max(self.packet_size_fwd_list)
            self.fwd_packet_length_min = min(self.packet_size_fwd_list)
            self.fwd_packet_length_mean = sum(self.packet_size_fwd_list) / len(self.packet_size_fwd_list)
            if len(self.packet_size_fwd_list) > 1:
                self.fwd_packet_length_std = statistics.stdev(self.packet_size_fwd_list)

            if self.fwd_iat_list:
                self.fwd_iat_total = sum(self.fwd_iat_list)
                self.fwd_iat_mean = sum(self.fwd_iat_list) / len(self.fwd_iat_list)
                if len(self.fwd_iat_list) > 1:
                    self.fwd_iat_std = statistics.stdev(self.fwd_iat_list)
                self.fwd_iat_max = max(self.fwd_iat_list)
                self.fwd_iat_min = min(self.fwd_iat_list)
            
            self.average_fwd_segment_size = sum(self.packet_size_fwd_list) / len(self.packet_size_fwd_list)

        if self.packet_size_bwd_list:
            self.bwd_packet_length_max = max(self.packet_size_bwd_list)
            self.bwd_packet_length_min = min(self.packet_size_bwd_list)
            self.bwd_packet_length_mean = sum(self.packet_size_bwd_list) / len(self.packet_size_bwd_list)
            if len(self.packet_size_bwd_list) > 1:
                self.bwd_packet_length_std = statistics.stdev(self.packet_size_bwd_list)

            if self.bwd_iat_list:
                self.bwd_iat_total = sum(self.bwd_iat_list)
                self.bwd_iat_mean = sum(self.bwd_iat_list) / len(self.bwd_iat_list)
                if len(self.bwd_iat_list) > 1:
                    self.bwd_iat_std = statistics.stdev(self.bwd_iat_list)
                self.bwd_iat_max = max(self.bwd_iat_list)
                self.bwd_iat_min = min(self.bwd_iat_list)

            self.average_bwd_segment_size = sum(self.packet_size_bwd_list) / len(self.packet_size_bwd_list)

        if self.flow_iat_list:
            self.flow_iat_mean = sum(self.flow_iat_list) / len(self.flow_iat_list)
            if len(self.flow_iat_list) > 1:
                self.flow_iat_std = statistics.stdev(self.flow_iat_list)
            self.flow_iat_max = max(self.flow_iat_list)
            self.flow_iat_min = min(self.flow_iat_list)

        self.average_packet_size = sum(self.packet_size_list) / (self.total_fwd_packets + self.total_bwd_packets) 
        self.min_packet_length = min(self.packet_size_list)
        self.max_packet_length = max(self.packet_size_list)
        self.packet_length_mean = sum(self.packet_size_list) / len(self.packet_size_list)
        if len(self.packet_size_list) > 1:
            self.packet_length_std = statistics.stdev(self.packet_size_list)
        if len(self.packet_size_list) > 1:
            self.packet_length_variance = statistics.variance(self.packet_size_list)


    def tcp_reconstruction(self, filename):
        self.reset_tcp_reassembly()
        self.file_stream = open(filename, "wb")

        # Clean the linked list

    def reset_tcp_reassembly(self):
        for i in range(2):
            self.sequenceNumber[i] = 0
            self.source_address[i] = 0
            self.source_port[i] = 0
            self.tcp_port[i] = 0
            self.bytes_written[i] = 0
            current = self.frags[i]

            while current is not None:
                next_frag = current.next
                current.data = None
                current = None
                current = next_frag

            self.frags[i] = None

        self.empty_tcp_stream = True
        self.incomplete_tcp_stream = False


    def close(self):
        if not self.closed:
            self.file_stream.close()
            self.reset_tcp_reassembly()
            self.closed = True

    def __del__(self):
        self.close()

        # Writes the payload data to the file
    def write_packet_data(self, index, data):
        # Ignore empty packets
        if len(data) == 0:
            return
        self.file_stream.write(bytes(data))
        self.bytes_written[index] += len(data)
        self.empty_tcp_stream = False

    def get_timestamp_string(self):
        three_hours = timedelta(hours=3)
        converted_date_time = datetime.fromtimestamp(self.flow_start_time) - three_hours
        return converted_date_time.strftime("%d.%m.%Y %H:%M:%S")


    def get_fwd_packets_per_second(self):
        # Duration is in milliseconds, therefore packets per seconds = packets / (duration / 1000)
        duration_in_milliseconds = (datetime.fromtimestamp(self.flow_last_seen) - datetime.fromtimestamp(self.flow_start_time)).total_seconds() * 1000
        if duration_in_milliseconds > 0:
            return self.total_fwd_packets / (duration_in_milliseconds / 1000)
        else:
            return 0

    def get_bwd_packets_per_second(self):
        # Duration is in milliseconds, therefore packets per seconds = packets / (duration / 1000)
        duration_in_milliseconds = (datetime.fromtimestamp(self.flow_last_seen) - datetime.fromtimestamp(self.flow_start_time)).total_seconds() * 1000
        if duration_in_milliseconds > 0:
            return self.total_bwd_packets / (duration_in_milliseconds / 1000)
        else:
            return 0

    def get_flow_bytes_per_second(self):
        # Duration is in milliseconds, therefore bytes per seconds = bytes / (duration / 1000)
        duration = (datetime.fromtimestamp(self.flow_last_seen) - datetime.fromtimestamp(self.flow_start_time)).total_seconds() * 1000
        if duration > 0:
            res = self.total_length_of_fwd_packets + self.total_length_of_bwd_packets
            res = res / (duration / 1000)
            return res
        else:
            return 0


    def get_packets_per_second(self):
        # Duration is in milliseconds, therefore bytes per seconds = bytes / (duration / 1000)
        duration = (datetime.fromtimestamp(self.flow_last_seen) - datetime.fromtimestamp(self.flow_start_time)).total_seconds() * 1000
        if duration > 0:
            res = self.total_fwd_packets + self.total_bwd_packets
            res = res / (duration / 1000)
            return res
        else:
            return 0


    def reassemble_packet(self, packet, pcap_time_val):
        ip = packet.getlayer(IP)
        if ip is not None:
            tcp_packet = packet.getlayer(TCP)

            # If the payload length is zero, bail out
            # length = len(tcp_packet.BytesHighPerformance) - tcp_packet.Header.Length
            # if length == 0:
            #     return

            self.reassemble_tcp(
                tcp_packet.seq,
                # len(tcp_packet.BytesHighPerformance),
                len(tcp_packet.payload),
                tcp_packet.payload,
                len(tcp_packet.payload),
                int(bool(tcp_packet.flags & 0x01)),
                int.from_bytes(socket.inet_aton(ip.src), byteorder='big'),
                int.from_bytes(socket.inet_aton(ip.dst), byteorder='big'),
                tcp_packet.sport,
                tcp_packet.dport
            )

            # Update sqrt
            if self.total_fwd_packets == 0 and self.total_bwd_packets == 0:
                self.flow_start_time = pcap_time_val
                self.flow_last_seen = self.flow_start_time

            flow_duration = (datetime.fromtimestamp(pcap_time_val) - datetime.fromtimestamp(self.flow_start_time)).total_seconds() * 1000
            if flow_duration > 120000000:
                return

            self.total_packets += 1

            duration = (datetime.fromtimestamp(pcap_time_val) - datetime.fromtimestamp(self.flow_last_seen)).total_seconds() * 1000
            # In order not to write duration = 0 for the first packet in the session
            if self.total_fwd_packets + self.total_bwd_packets > 0:
                self.flow_iat_list.append(duration)

            self.flow_last_seen = pcap_time_val

            # Process subflows0
            current_ts = datetime.fromtimestamp(pcap_time_val).timestamp() * 1000
            if self.subflow_count == -1:
                self.subflow_start_time_ts = current_ts
                self.subflow_last_seen_ts = current_ts
            delta = current_ts - self.subflow_last_seen_ts
            expr = (current_ts - self.subflow_last_seen_ts) / 1000000
            if expr > 1.0:
                self.subflow_count += 1
                self.subflow_start_time_ts = current_ts
            self.subflow_last_seen_ts = current_ts

                # In the original research there is a peculiarity (error) in determining the length of a TCP packet
                # if the IP length is <46 bytes.
                # Ethernet adds padding up to 46 bytes, and this padding counts as the length of the TCP payload
            length = len(tcp_packet.payload)
            if len(ip) < 46:
                length = 46 - len(ip)

            # Forward
            if int.from_bytes(socket.inet_aton(ip.src), byteorder='big') == self.source_address[0] and tcp_packet.sport == self.source_port[0]:
                if self.total_fwd_packets == 0:
                    self.fwd_start_time = pcap_time_val
                    self.fwd_last_seen = self.fwd_start_time
                else:
                    fwd_duration = (datetime.fromtimestamp(pcap_time_val) - datetime.fromtimestamp(self.fwd_last_seen)).total_seconds() * 1000
                    self.fwd_iat_list.append(fwd_duration)
                    self.fwd_last_seen = pcap_time_val

                self.total_fwd_packets += 1
                self.total_length_of_fwd_packets += length
                self.packet_size_fwd_list.append(length)
                self.fwd_header_length += tcp_packet.dataofs * 4

                # Backward
            if int.from_bytes(socket.inet_aton(ip.src), byteorder='big') == self.source_address[1] and tcp_packet.sport == self.source_port[1]:
                if self.total_bwd_packets == 0:
                    self.bwd_start_time = pcap_time_val
                    self.bwd_last_seen = self.bwd_start_time
                else:
                    bwd_duration = (datetime.fromtimestamp(pcap_time_val) - datetime.fromtimestamp(self.bwd_last_seen)).total_seconds() * 1000
                    self.bwd_iat_list.append(bwd_duration)
                    self.bwd_last_seen = pcap_time_val

                self.total_bwd_packets += 1
                self.total_length_of_bwd_packets += length
                self.packet_size_bwd_list.append(length)
                self.bwd_header_length += tcp_packet.dataofs * 4

            # FIN flags
            if int(bool(tcp_packet.flags & 0x01)):
                self.fin_flag_count += 1


    def reassemble_tcp(self, packetSequenceNumber, packetLength, packetData,
                  packetDataLength, synFlag, 
                  packetSourceAddress, packetDestinationAddress, 
                  packetSourcePort, packetDestinationPort):
        sourceIndex = -1
        first = False
        newseq = None
        tmp_frag = None

        for j in range(2):
            if (self.source_address[j] == packetSourceAddress and
                    self.source_port[j] == packetSourcePort):
                sourceIndex = j

        if sourceIndex < 0:
            for j in range(2):
                if self.source_port[j] == 0:
                    self.source_address[j] = packetSourceAddress
                    self.source_port[j] = packetSourcePort
                    sourceIndex = j
                    first = True
                    break
        if sourceIndex < 0:
            raise Exception("ERROR in ReassembleTcp: Too many addresses!")

        if packetDataLength < packetLength:
            incomplete_tcp_stream = True

        if first:
            self.sequenceNumber[sourceIndex] = packetSequenceNumber + packetLength
            if synFlag:
                self.sequenceNumber[sourceIndex] += 1
            self.write_packet_data(sourceIndex, packetData)
            return

        if packetSequenceNumber < self.sequenceNumber[sourceIndex]:
            newseq = packetSequenceNumber + packetLength
            if newseq > self.sequenceNumber[sourceIndex]:
                new_len = self.sequenceNumber[sourceIndex] - packetSequenceNumber
                if packetDataLength <= new_len:
                    packetData = None
                    packetDataLength = 0
                    incomplete_tcp_stream = True
                else:
                    packetDataLength -= new_len
                    tmpData = packetData[new_len:]
                    packetData = tmpData
                packetSequenceNumber = self.sequenceNumber[sourceIndex]
                packetLength = newseq - self.sequenceNumber[sourceIndex]

        if packetSequenceNumber == self.sequenceNumber[sourceIndex]:
            self.sequenceNumber[sourceIndex] += packetLength
            if synFlag:
                self.sequenceNumber[sourceIndex] += 1
            if packetData:
                self.write_packet_data(sourceIndex, packetData)
            while self.check_fragments(sourceIndex):
                pass
        else:
            if (packetDataLength > 0 and packetSequenceNumber > self.sequenceNumber[sourceIndex]):
                tmp_frag = TcpFragment()
                tmp_frag.data = packetData
                tmp_frag.seq = packetSequenceNumber
                tmp_frag.len = packetLength
                tmp_frag.dataLength = packetDataLength
                if self.frags[sourceIndex]:
                    tmp_frag.next = self.frags[sourceIndex]
                else:
                    tmp_frag.next = None
                self.frags[sourceIndex] = tmp_frag


        # Here we search through all the frag we have collected to see if one fits
    def check_fragments(self, index):
        prev = None
        current = self.frags[index]
        while current:
            if current.seq == self.sequenceNumber[index]:
                if current.data:
                    self.write_packet_data(index, current.data)
                self.sequenceNumber[index] += current.len
                if prev:
                    prev.next = current.next
                else:
                    self.frags[index] = current.next
                current.data = None
                current = None
                return True
            prev = current
            current = current.next
        return False
