# -*- coding:utf-8 -*-
import socket
import ctypes
import struct
import time

class UDPScaner(object):
    class ICMP(ctypes.Structure):
        _fields_ = [
            ('type', ctypes.c_ubyte),
            ('code', ctypes.c_ubyte),
            ('checksum', ctypes.c_ushort),
            ('unused', ctypes.c_ushort),
            ('next_hop_mtu', ctypes.c_ushort)
        ]

        def __new__(self, socket_buffer):
            return self.from_buffer_copy(socket_buffer)

        def __init__(self, socket_buffer):
            pass
    #############################################################################################
    def __init__(self, host, port):
        super(UDPScaner, self).__init__()

        self.host = host
        self.port = port

    #############################################################################################
    def scan(self):
        '''
        :return: 1.True:目标端口开放  2.False:目标端口关闭
        '''
        soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        soc.settimeout(0)
        soc.bind(("0.0.0.0", 0))

        # include the IP headers in the captured packets
        soc.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        count = 0
        while count < 4:
            count += 1
            self.udp_sender()
            timestamp = time.time()
            while time.time() - timestamp < 0.5:
                try:
                    # read in a single packet
                    pkt = soc.recvfrom(65565)
                    if self.packet_handler(pkt[0]):
                        #recv icmp
                        soc.close()
                        return False
                except Exception, e:
                    continue
        soc.close()
        return True

    #############################################################################################
    def packet_handler(self, pkt):
        #parse ip header
        if len(pkt) < 56:
            return
        ip_header = pkt[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        # Create our IP structure
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        detect_dport = struct.unpack(">h", pkt[-6:-4])[0]

        print 'IP -> Version:' + str(version) + ', Header Length:' + str(ihl) + \
              ', TTL:' + str(ttl) + ', Protocol:' + str(protocol) + ', Source:' \
              + str(s_addr) + ', Destination:' + str(d_addr)

        # Create our ICMP structure
        buf = pkt[iph_length:iph_length + ctypes.sizeof(UDPScaner.ICMP)]
        icmp_header = UDPScaner.ICMP(buf)

        print "ICMP -> Type: %d, Code: %d, dport: %d" % (icmp_header.type, icmp_header.code, detect_dport) + '\n'

        if str(s_addr) == self.host and icmp_header.type == 3 and icmp_header.code == 3 and detect_dport == self.port:
            return True

        return False

    #############################################################################################
    def udp_sender(self):
        soc = None
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            soc.sendto("1234567890", (self.host, self.port))
        except Exception, e:
            print "Send udp packet failed. Exception: %s" % str(e)
        soc.close()
        return

#############################################################################################
class TCPScanner(object):
    def __init__(self, host, port):
        super(TCPScanner, self).__init__()

        self.host = host
        self.port = port

    #############################################################################################
    def scan(self):
        '''
        :return: 1.True:目标端口开放  2.False:目标端口关闭
        '''
        count = 0
        soc   = None
        while count < 5:
            count += 1
            try:
                soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                soc.settimeout(1)
                soc.connect((self.host, self.port))
            except Exception, e:
                continue
            soc.close()
            return True
        if soc is not None:
            soc.close()
        return False








