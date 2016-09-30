# -*- coding:utf-8 -*-

from sulley import *
from scapy.all import *
from scapy.layers import *
import random

s_initialize("SNMP_Request")
s_bit_field(value=48, width=8, fuzzable=False, name="head_type")
s_bit_field(value=0, width=8, name="packet_length")
s_binary("02 01", name="ver_type")
s_bit_field(value=1, width=8, val_range=(0, 2), name="ver")
s_binary("04 06 70 75 62 6c 69 63", name="community")
s_binary("a0", name="get-request")
s_bit_field(value=53, width=8, name="request_length")
s_binary("02 01 00 02 01 00 02 01 00")
s_binary("30")
s_bit_field(value=42, width=8, name="vars_length")

s_initialize("OID")
s_binary("30")
s_bit_field(value=12, width=8, name="item_length")
s_bit_field(value=6, width=8, name="item_type")
s_bit_field(value=8, width=8, name="oid_length")
s_random("2b06010201010100", min_length=0, max_length=1000, name="oid")
s_binary("05", name="val_type")
s_bit_field(value=42, width=8, name="val_length")
s_random("2b06010201010100", min_length=0, max_length=1000, name="val")


class Fuzzer(object):
	def __init__(self):
		self.data = None

	def block_mutate_callback(self, block):
		

	def pre_send_callback(self, sock, blockName, data):
		self.data = data
		oid_block = s_get("OID")

		count = random.randint(0, 5)
		for i in xrange(0, count):
			oid_block.mutate()
			self.data += oid_block.render()

		print "SNMP Length:" + str(len(self.data))
		return self.data

	def fetch_proc_crash_callback(self, report):
		print s_hex_dump(self.data)
		return False

if __name__ == '__main__':
    fuzz = Fuzzer()
    sess = sessions.session(proto="udp", keep_alive=False)

    sess.block_mutate_callback = fuzz.block_mutate_callback
    sess.pre_send_callback = fuzz.pre_send_callback
    sess.fetch_proc_crash_callback = fuzz.fetch_proc_crash_callback

    target = sessions.target("10.0.0.36", 161)
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

    sess.add_block(s_get("SNMP_Request"))
    sess.add_target(target)

    sess.fuzz()