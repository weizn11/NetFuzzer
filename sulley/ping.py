# -*- coding:utf-8 -*-

import os
import socket
import struct
import select
import time

ICMP_ECHO_REQUEST = 8  # Platform specific

class Pinger(object):
    """ Pings to a host -- the Pythonic way"""
    def __init__(self, target_host, timeout=1):
        self.target_host = target_host
        self.timeout = timeout

    def do_checksum(self, source_string):
        """  Verify the packet integritity """
        sum = 0
        max_count = (len(source_string) / 2) * 2
        count = 0
        while count < max_count:  # 分割数据每两比特(16bit)为一组
            val = ord(source_string[count + 1]) * 256 + ord(source_string[count])
            sum = sum + val
            sum = sum & 0xffffffff
            count = count + 2

        if max_count < len(source_string):  # 如果数据长度为基数,则将最后一位单独相加
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff

        sum = (sum >> 16) + (sum & 0xffff)  # 将高16位与低16位相加直到高16位为0
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer  # 返回的是十进制整数

    def receive_ping(self, sock, ID, timeout):
        """
        Receive ping from the socket.
        """
        time_remaining = timeout
        while True:
            start_time = time.time()
            readable = select.select([sock], [], [], time_remaining)
            time_spent = (time.time() - start_time)
            if readable[0] == []:  # Timeout
                return

            time_received = time.time()
            recv_packet, addr = sock.recvfrom(1024)
            icmp_header = recv_packet[20:28]
            type, code, checksum, packet_ID, sequence = struct.unpack(
                "bbHHh", icmp_header
            )
            if packet_ID == ID:
                bytes_In_double = struct.calcsize("d")
                time_sent = struct.unpack("d", recv_packet[28:28 + bytes_In_double])[0]
                return time_received - time_sent

            time_remaining = time_remaining - time_spent
            if time_remaining <= 0:
                return

    def send_ping(self, sock, ID):
        """
        Send ping to the target host
        """
        target_addr = socket.gethostbyname(self.target_host)

        my_checksum = 0

        # Create a dummy heder with a 0 checksum.
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
        bytes_In_double = struct.calcsize("d")
        data = (192 - bytes_In_double) * "Q"
        data = struct.pack("d", time.time()) + data

        # Get the checksum on the data and the dummy header.
        my_checksum = self.do_checksum(header + data)
        header = struct.pack(
            "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
        )
        packet = header + data
        sock.sendto(packet, (target_addr, 1))

    def ping(self):
        """
        Returns the delay (in seconds) or none on timeout.
        """
        sock = None
        icmp = socket.getprotobyname("icmp")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error, (errno, msg):
            if errno == 1:
                # Not superuser, so operation not permitted
                msg += "ICMP messages can only be sent from root user processes"
                raise socket.error(msg)
        except Exception, e:
            print "Exception: %s" % (e)
            raise e

        my_ID = os.getpid() & 0xFFFF
        self.send_ping(sock, my_ID)
        delay = self.receive_ping(sock, my_ID, self.timeout)
        sock.close()
        return delay
