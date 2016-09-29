import threading
import time
from scapy.all import *

class Sniffer(threading.Thread):
    def __init__(self,iface,filter,sniff_stop_filter,timeout):
        super(Sniffer,self).__init__()
        self.iface = iface
        self.active = True
        self.stopFlag = False
        self.filter = filter
        self.sniff_stop_filter = sniff_stop_filter
        self.timeout = timeout

    def packet_handler_callback(self,pkt):
        pass

    def run(self):
        while self.active:
            try:
                recv_packet = sniff(iface=self.iface,filter=self.filter,store=0,
                                    prn=self.packet_handler_callback,stop_filter=self.sniff_stop_filter,timeout=self.timeout)
            except Exception, e:
                print "sniffer start error.\nTrace info:"
                print e
                os._exit(0)

        self.stopFlag = True

    def stop(self):
        self.active = False
        while not self.stopFlag:
            time.sleep(0.001)

        return

