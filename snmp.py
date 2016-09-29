# -*- coding:utf-8 -*-

from sulley import *
from scapy.all import *
from scapy.layers import *
import random

s_initialize("SNMP_OID")
s_int(0, val_range=(0, 5000), name="length")
s_int(0, val_range=(0, 100), name="oid_node")

s_initialize("SNMP_REQ_VAL")
s_string("123", max_len=5000, name="oid_val")

class Fuzzer(object):
	def __init__(self):
		self.oid = ""
		self.length = 0
		self.oid_head = "1.3.6.1.4.1.9.9.491.1.3.3.1.1.5.9"
		self.packet = None

	def block_mutate_callback(self, block):
		self.oid = ""
		self.length = block.get_field_value("length")

		for i in range(0, self.length):
			if len(self.oid) > 0:
				self.oid += "."

			self.oid += str(block.get_field_value("oid_node"))
			block.mutate()

		print "OID length :" + str(len(self.oid.split(".")))

	def ex_send_callback(self, target, data):
		req_val_block = s_get("SNMP_REQ_VAL")
		req_val_block.mutate()

		oid_fuzz = self.oid_head + "." + str(self.length) + "." + self.oid

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
        "gdb_path" : "/usr/bin/gdb",
        "debug_file" : "",
        "gdb_cmd" : ["target remote 192.168.56.1:1111", "i r", "c"],
        "proc_args" : "",
        "crash_cmd" : ["bt","info reg"],
        "continue_spacing" : 0.3
    }

    sess.add_block(s_get("SNMP_OID"))
    sess.add_target(target)

    sess.fuzz()