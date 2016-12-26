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
		self.pkt_file = open("snmp_2", "w")

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

	def detected_target_crash_callback(self, fuzzStoreList):
		dump_fuzz_store_list("snmp_crash.txt", fuzzStoreList)
		return False

if __name__ == '__main__':
    fuzz = Fuzzer()
    sess = sessions.session(proto="udp", keep_alive=False,
            loop_sleep_time=0.00, fuzz_store_limit=1000, pinger_threshold=100, sock_timeout=2)

    sess.pre_send_callback                    = fuzz.pre_send_callback
    sess.detected_target_crash_callback       = fuzz.detected_target_crash_callback

    target = sessions.target("10.0.0.34", 161)
    fuzz.target = target

    sess.add_block(s_get("SNMP_Request"))
    sess.add_target(target)

    sess.fuzz()
