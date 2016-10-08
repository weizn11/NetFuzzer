# -*- coding:utf-8 -*-
from sulley import *
from scapy.all import *
from scapy.layers import *
import random

s_initialize("SNMP_OID")
s_int(0, val_range=(50, 200), wild=True, name="length")
s_int(0, val_range=(0, 100), wild=True, name="oid_node")

s_initialize("SNMP_REQ_VAL")
s_string("123", max_len=200, name="oid_val")

s_initialize("OID_NODE_VAL")
s_int(1, val_range=(0, 500), wild=True, name="value")
s_int(1, val_range=(0, 10), wild=True, name="count")

class Fuzzer(object):
	def __init__(self):
		self.overflow = ""
		self.length = 0
		self.oid_head = ""
		self.packet = None
		self.oid_cisco = "1.3.6.1.4.1.9.9.491.1.3.3.1.1.5.9"

	def block_mutate_callback(self, block):
		self.overflow = ""
		self.oid_head = self.oid_cisco

		blockOidVal = s_get("OID_NODE_VAL")
		blockOidVal.mutate()

		oid_count = blockOidVal.get_field_value("count")
		for i in xrange(0, oid_count):
			blockOidVal.mutate("value")
			self.oid_head += "." + str(blockOidVal.get_field_value("value"))

		self.length = block.get_field_value("length")
		for i in range(0, self.length):
			if len(self.overflow) > 0:
				self.overflow += "."

			self.overflow += str(block.get_field_value("oid_node"))
			block.mutate("oid_node")

		print "OID length :" + str(len(self.overflow.split(".")))

	def ex_send_callback(self, target, data):
		req_val_block = s_get("SNMP_REQ_VAL")
		req_val_block.mutate()

		oid_fuzz = self.oid_head + "." + str(self.length) + "." + self.overflow

		print "FUZZ Length: " + str(len(oid_fuzz))

		snmpBulk = SNMPbulk(id=random.randint(0x80000, 0x1fffffff), max_repetitions=1, varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1"), value=ASN1_STRING(req_val_block.render())),

                                                                                     SNMPvarbind(oid=ASN1_OID(oid_fuzz))])
		snmp = SNMP(PDU=snmpBulk)
		packet = IP(dst=target.host) / UDP(dport=target.port, sport=12345) / snmp
		send(packet, verbose=False, iface="eth0")
		self.packet = packet

	def fetch_proc_crash_callback(self, report):
		print report
		self.packet.show()
		return False



if __name__ == '__main__':
    fuzz = Fuzzer()
    sess = sessions.session(proto="custom", keep_alive=False)

    sess.ex_send_callback = fuzz.ex_send_callback
    sess.block_mutate_callback = fuzz.block_mutate_callback
    sess.fetch_proc_crash_callback = fuzz.fetch_proc_crash_callback

    target = sessions.target("10.0.0.36", 161)
    target.procmon = pedrpc.client("127.0.0.1", 7437)
    target.procmon_options = \
    {
        "path" : "/usr/bin/gdb",
        "cmdline" : [],
        "stdin" : ["target remote 192.168.56.1:1111", "i r", "c"],
        "crash_cmd" : ["bt","info reg"],
        "continue_spacing" : 0.3,
        "crash_code" : ["(gdb)", ],
        "match_logic" : 1
    }

    sess.add_block(s_get("SNMP_OID"))
    sess.add_target(target)

    sess.fuzz()