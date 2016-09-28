#!/usr/bin/env python
# -*- coding:utf-8 -*-
import time
import sys
from sulley import *
import binascii
import os
from sulley import blocks
import gc


SLEEP_TIME = 0
TIMEOUT = 5

#设置测试用例总数
set_max_mutations(10000000)

#定义测试数据结构
s_initialize("Fuzz_test")
#s_static("test")
s_int(100,endian="<",format="binary",fuzzable=False,val_range=(1,100000),name="len")
'''
s_int(100,fuzzable=False,val_range=(1,100000))
s_string("test",max_len=100)
s_static("@")
s_string("360",max_len=100)
s_static(".")
s_string("com",max_len=100)
'''

class fuzzer():
    def __init__(self):
        self.data = None
        self.reconnCount = 0

    def post_send_callback(self,sock,data):
        self.data=data
        try:
            recvBuff = sock.recv(65536)
            if len(recvBuff)>1:
                print "length:",len(recvBuff),"\t",recvBuff
            else:
                pass
        except:
            print "crash data:\n", binascii.b2a_hex(self.data), "\n\nlength:", len(self.data)
            os._exit(0)
            pass
        return False

    def connect_failed_callback(self,sock,target):
        if self.reconnCount > 5:
            print "crash data:\n", binascii.b2a_hex(self.data), "\n\nlength:", len(self.data)
            os._exit(0)
        self.reconnCount+=1
        time.sleep(2)
        return True

    def send_failed_callback(self,target,data):
        return True

    def sniff_packet_handler(self,pkt):
        print len(pkt)

block = s_get("Fuzz_test")
block.mutate()
num = 100
print "data:\n"

f = fuzzer()

sess = sessions.session(sleep_time=SLEEP_TIME, sock_timeout=TIMEOUT,proto="tcp",sniff_switch=False,keep_alive=False,sniff_device="lo")

sess.add_block(s_get("Fuzz_test"))
sess.post_send_callback = f.post_send_callback
sess.connect_failed_callback=f.connect_failed_callback
sess.send_failed_callback=f.send_failed_callback
sess.packet_handler_callback=f.sniff_packet_handler

target = sessions.target("127.0.0.1", 74)
target.procmon = pedrpc.client("127.0.0.1",7777)
target.procmon_options = \
    {
        "gdb_path" : "/usr/bin/gdb",
        "debug_file" : "/home/weizn/Desktop/C_Projects/proto_test/bin/Release/proto_test",
        "gdb_cmd" : [],
        "proc_args" : "",
        "crash_cmd" : ["bt","info reg"],
        "continue_spacing" : 0.5
    }
sess.add_target(target)

sess.fuzz()























