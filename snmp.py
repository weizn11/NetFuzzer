# -*- coding:utf-8 -*-

from sulley import *
from scapy.all import *
from scapy.layers import *
import random
import binascii
import time
import threading

s_initialize("SNMP_Request")
s_bit_field(value=48, width=8, fuzzable=False, name="head_type")
s_bit_field(value=0, width=8, name="packet_length")
s_binary("02 01", name="ver_type")
s_bit_field(value=1, width=8, val_range=(0, 2), wild=True, name="ver")
s_binary("04 06 70 75 62 6c 69 63", name="community")
s_binary("a0", name="get-request")
s_bit_field(value=53, width=8, name="request_length")
s_binary("02 01 00 02 01 00 02 01 00")

s_binary("30")
s_bit_field(value=42, width=8, name="var-bindings_length")


s_initialize("OID")
s_binary("30")
s_bit_field(value=12, width=8, name="item_length")
s_bit_field(value=6, width=8, fuzzable=False, name="item_type")

s_bit_field(value=8, width=8, name="oid_length")
s_random("2b06010201010100", min_length=0, max_length=150, name="oid")

s_binary("05", name="val_type")
s_bit_field(value=42, width=8, name="val_length")
s_random("2b06010201010100", min_length=0, max_length=150, name="val")


class Fuzzer(object):
	def __init__(self):
		self.data = None
		self.icmp = False
		self.target = None
		self.mutex = threading.Lock()
		self.pkt_file = open("snmp_1", "w")

	def block_mutate_callback(self, block):
		pass

	def pre_send_callback(self, sock, block, data):
		bindings_length = 0
		bindings = ""
		oid_block = s_get("OID")
		tmp = 0

		while True:
			bindings_length = 0
			self.data = ""
			bindings = ""
			tmp = 0

			count = random.randint(1, 10)

			for i in xrange(0, count):
				while True:
					oid_block.mutate()
					#oid_block.set_field_value("oid", binascii.a2b_hex("2b06010201010100"))
					#oid_block.set_field_value("val", "")

					if (len(oid_block.get_field_value("oid")) + len(oid_block.get_field_value("val")) + 4) > 220 / count:
						continue

					tmp = random.randint(0, 1)
					if tmp < 15:
						oid_block.set_field_value("item_length", len(oid_block.get_field_value("oid")) + len(oid_block.get_field_value("val")) + 4)

					tmp = random.randint(0, 1)
					if tmp < 15:
						oid_block.set_field_value("oid_length", len(oid_block.get_field_value("oid")))
					#print "oid_length:" + str(len(oid_block.get_field_value("oid")))

					tmp = random.randint(0, 1)
					if tmp < 15:
						oid_block.set_field_value("val_length", len(oid_block.get_field_value("val")))
					#print "val_length:" + str(len(oid_block.get_field_value("val")))
					break

				bindings_length += oid_block.get_field_value("item_length") + 2
				bindings += oid_block.render()

			tmp = random.randint(0, 15)
			if tmp < 15:
				block.set_field_value("var-bindings_length", len(bindings))

			tmp = random.randint(0, 15)
			if tmp < 15:
				block.set_field_value("packet_length", len(bindings) + 24)
			
			tmp = random.randint(0, 15)
			if tmp < 15:
				block.set_field_value("request_length", len(bindings) + 11)

			self.data = block.render() + bindings

			if len(self.data) < 256:
				break

		#print "packet_length:" + str(block.get_field_value("packet_length"))
		print "item counts:" + str(count)
		print "SNMP Length:" + str(len(self.data))
		return self.data

	def fetch_proc_crash_callback(self, report):
		print binascii.b2a_hex(self.data)
		return False

	def post_send_callback(self, sock, data):
		timestamp = 0
		resendCount = 0

		self.pkt_file.write(binascii.b2a_hex(data))
		self.pkt_file.write("\n")
		self.pkt_file.flush()

		while True:
			self.icmp = False
			packet = IP(dst=self.target.host) / ICMP()
			send(packet, verbose=False)

			timestamp = time.time()
			while True:
				if self.mutex.acquire():
					if self.icmp:
						self.mutex.release()
						return (False, False)
					else:
						self.mutex.release()
						if time.time() - timestamp >= 1:
							break

			if resendCount >= 5:
				print "target crash!"
				self.pkt_file.close()
				os._exit(0)
			resendCount += 1
			print "resend icmp."

	def packet_handler_callback(self, pkt):
		try:
			if pkt[IP].src == self.target.host:
				if pkt[ICMP]:
					if self.mutex.acquire():
						self.icmp = True
						self.mutex.release()
				else:
					if self.mutex.acquire():
						self.icmp = False
						self.mutex.release()
		except:
			if self.mutex.acquire():
				self.icmp = False
				self.mutex.release()

if __name__ == '__main__':
    fuzz = Fuzzer()
    sess = sessions.session(proto="udp", keep_alive=False, loop_sleep_time=0.0, sniff_switch=True, sniff_filter="icmp")

    sess.block_mutate_callback = fuzz.block_mutate_callback
    sess.pre_send_callback = fuzz.pre_send_callback
    #sess.fetch_proc_crash_callback = fuzz.fetch_proc_crash_callback
    sess.post_send_callback = fuzz.post_send_callback
    sess.packet_handler_callback = fuzz.packet_handler_callback

    target = sessions.target("10.0.0.36", 161)
    fuzz.target = target
    '''
    target.procmon = pedrpc.client("127.0.0.1", 7437)
    target.procmon_options = \
    {
        "gdb_path" : "/usr/bin/gdb",
        "debug_file" : "",
        "gdb_cmd" : ["target remote 192.168.56.1:1111", "i r", "c"],
        "proc_args" : "",
        "crash_cmd" : ["bt","info reg"],
        "continue_spacing" : 0.3
    }
    '''
    sess.add_block(s_get("SNMP_Request"))
    sess.add_target(target)

    sess.fuzz()