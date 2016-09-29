#!/usr/bin/env python
# -*- coding:utf-8 -*-
import time
import sys
from sulley import *
import binascii
import os
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
import threading

SLEEP_TIME = 0
TIMEOUT = 5

#设置生成测试实例个数
set_max_mutations(999999999)

s_initialize("IKEv1_SA")
s_random("cd 02 32 6f 14 a9 5b 93",min_length=8,max_length=8)
s_binary("00000000000000000110020000000000000001680d00013400000001"
"000000010000012801010008030000240101000080010005800200028003000180040002800b0001000c0004000070800300"
"00240201000080010005800200018003000180040002800b0001000c0004000070800300002403010000800100018002000280"
"03000180040002800b0001000c000400007080030000240401000080010001800200018003000180040002800b0001000c00040000"
"7080030000240501000080010005800200028003000180040001800b0001000c0004000070800300002406010000800100058002000180"
"03000180040001800b0001000c000400007080030000240701000080010001800200028003000180040001800b0001000c00040000708000"
"0000240801000080010001800200018003000180040001800b0001000c000400007080000000184048b7d56ebce88525e7de7f00d6c2d3c0000000")

#定义数据结构
s_initialize("IKEv1_HDR")   #初始化一个数据结构
s_binary("00 00 00 00 00 00 00 00",name="init_cookie")
s_binary("00 00 00 00 00 00 00 00",name="respo_cookie")
s_binary("8410020000000000")
s_int(0,name="length",fuzzable=False)

s_initialize("FRAGMENT_HDR")
s_binary("00 00")
s_word(0,endian=">",val_range=(0,232),name="length")
s_word(0,endian=">",fuzzable=False,name="ID")
s_byte(0,fuzzable=False,name="Number")
s_byte(0,fuzzable=False,name="Flags")

payload_ikev1_ex=("{init_cookie}{responder_cookie}0410020000000000000000e00a0000643bce03faae189d2b151a4"
"d527d6122a23b87fb1344d4084bd6e2605cd5615d096d56f31a96c700ee4f21da4fb1f05503d775bf4f392bf1580ab2f7e3fb34616b0"
"312308bbd098e0c2982513f8e72fc32af003ec1136fd7ac6ff6bae8cf7108b10d0000186ea7c7ed3ca3383538801b4b32a5aba1618077650d"
"00001412f5f28c457168a9702d9fe274cc01000d000014afcad71368a1f1c96b8696fc775701000d0000143ac5957214a85b93db6a509869fdb3"
"300000000c09002689dfd6b712")

ikev1_hdr_str = ("{init_cookie}{responder_cookie}8410020000000000{length}")

fragment_header=("0000{length}00{id}{num}{flag}")

class fuzzer():
    def __init__(self):
        self.target = None
        self.fuzz_count = 1
        self.blockName = ""
        self.data = None
        self.step1 = False
        self.mutex = threading.Lock()
        self.responder_cookie = None
        self.init_cookie = None
        self.resendCount = 0

        self.frag_num = 1

        global payload_ikev1_ex
        global ikev1_hdr_str

        self.ikev1_hdr = None
        self.frag_hdr = None
        self.payload = None
        self.silcePayload = None

        self.sendData = None

    def block_mutate_callback(self, block):
        if block.get_name == "FRAGMENT_HDR":
            if not self.payload:
                try:
                    self.payload = payload_ikev1_ex.format(init_cookie=binascii.b2a_hex(self.init_cookie),
                                                           responder_cookie=binascii.b2a_hex(self.responder_cookie))
                    self.payload = binascii.a2b_hex(self.payload)
                    print "payload len:",len(self.payload)
                    self.frag_num = 1
                except:
                    print "generate payload exception"
                    raise Exception

            block.set_field_data("ID",self.fuzz_count)
            block.set_field_data("Number",self.frag_num)
            self.frag_num += 1
            frag_length = block.get_field_data("length")

            print "frag_id:", self.fuzz_count, "\tfrag_length:", frag_length

            try:
                if frag_length - 8 >= len(self.payload):
                    self.ikev1_hdr = ikev1_hdr_str.format(init_cookie=binascii.b2a_hex(self.init_cookie),
                                                          responder_cookie=binascii.b2a_hex(self.responder_cookie),
                                                          length=("%08x" % (len(self.payload) + 36)))
                    self.ikev1_hdr = binascii.a2b_hex(self.ikev1_hdr)

                    block.set_field_data("Flags",1)
                    block.set_field_data("length",232)
                    self.frag_hdr = block.render()

                    self.sendData = self.ikev1_hdr + self.frag_hdr + self.payload
                    self.payload = None
                    self.fuzz_count += 1

                elif frag_length <= 8:
                    self.ikev1_hdr = ikev1_hdr_str.format(init_cookie=binascii.b2a_hex(self.init_cookie),
                                                          responder_cookie=binascii.b2a_hex(self.responder_cookie),
                                                          length=("%08x" % (36)))
                    self.ikev1_hdr = binascii.a2b_hex(self.ikev1_hdr)

                    block.set_field_data("Flags", 0)
                    self.frag_hdr = block.render()

                    self.sendData = self.ikev1_hdr + self.frag_hdr
                else:
                    self.silcePayload = self.payload[:frag_length-8]
                    self.payload = self.payload[frag_length-8:]

                    self.ikev1_hdr = ikev1_hdr_str.format(init_cookie=binascii.b2a_hex(self.init_cookie),
                                                          responder_cookie=binascii.b2a_hex(self.responder_cookie),
                                                          length=("%08x" % (len(self.silcePayload) + 36)))
                    self.ikev1_hdr = binascii.a2b_hex(self.ikev1_hdr)

                    block.set_field_data("Flags",0)
                    self.frag_hdr = block.render()

                    self.sendData = self.ikev1_hdr + self.frag_hdr + self.silcePayload

                #print "frag_hdr:",binascii.b2a_hex(self.sendData)
            except:
                print "fragment exception"
                raise Exception

    def post_send_callback(self,sock,data):
        self.data = data
        timeCount = 0

        if self.blockName == "FRAGMENT_HDR":
            if self.payload:
                return (False,True)
            else:
                return (False,False)
        else:
            while True:
                if self.blockName == "IKEv1_SA":
                    if self.mutex.acquire():
                        if self.step1:
                            self.step1 = False
                            self.mutex.release()
                            break
                            break
                    self.mutex.release()

                    time.sleep(0.001)
                    timeCount += 1
                    if timeCount*0.001 > 3:
                        print "request resend"
                        return (True,False)

        return (False,False)

    def packet_handler_callback(self,pkt):
        try:
            if pkt[IP].src == "10.0.0.34":
                if pkt[ISAKMP]:
                    if self.init_cookie <> pkt[ISAKMP].init_cookie:
                        return
                    if self.blockName == "IKEv1_SA":
                        try:
                            self.responder_cookie = pkt[ISAKMP].resp_cookie
                            vid = pkt[ISAKMP_payload_VendorID].vendorID
                            #print "FRAGMENTION SUPPORTED!\n",binascii.b2a_hex(self.init_cookie)

                            if self.mutex.acquire():
                                self.step1 = True
                                self.mutex.release()
                        except:
                            print "filter"
        except:
            print "parse error"

    def ex_send_callback(self, target, data):
        self.target = target
        packet = IP(dst=target.host)/UDP(sport=500, dport=500)/data
        send(packet, verbose=False)

    def pre_send_callback(self, sock, blockName, data):
        self.blockName = blockName
        if blockName == "IKEv1_SA":
            self.init_cookie = data[:8]
        elif blockName == "IKEv1_HDR":
            pass
        elif blockName == "FRAGMENT_HDR":
            if self.sendData:
                data = self.sendData
                self.sendData = None

        return data

def start_wait_callback():
    pass

#创建一个fuzzer实例
f1 = fuzzer()

#创建一个fuzz会话
sess1 = sessions.session(loop_sleep_time=SLEEP_TIME, sock_timeout=TIMEOUT,
                        proto="custom",sniff_device="eth0",sniff_switch=True,
                        keep_alive=False,sniff_filter="udp dst port 500 and src port 500")

#添加需要进行fuzz的数据结构
sess1.add_block(s_get("IKEv1_SA"))
#sess1.add_block(s_get("IKEv1_HDR"))
sess1.add_block(s_get("FRAGMENT_HDR"))

#设置回调函数
sess1.post_send_callback = f1.post_send_callback
sess1.packet_handler_callback = f1.packet_handler_callback
sess1.pre_send_callback = f1.pre_send_callback
sess1.block_mutate_callback = f1.block_mutate_callback
sess1.start_wait_callback = start_wait_callback
sess1.ex_send_callback = f1.ex_send_callback

#设置fuzz目标
target = sessions.target("10.0.0.34", 500)
sess1.add_target(target)

#开始fuzzing
sess1.fuzz()























