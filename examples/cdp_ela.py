# -*- coding:utf-8 -*-
from sulley import *
import binascii
import struct
import os

s_initialize("Packet_Header")
s_binary("01000ccccccc", name="dest_mac")
s_binary("000c29b6eda1", name="src_mac")
s_binary("0000", name="eth_length")
#LLC Protocl Header
s_binary("aaaa0300000c2000", name="LLC_Header")
#CDP Header
s_binary("02", name="CDP_Ver")
s_binary("b4", name="CDP_TTL")
s_binary("0000", name="CDP_Checksum")
#CDP Type Field
s_word(1, endian=">", fuzzable=False, val_range=(0, 16), name="CDP_Type")
s_binary("0006", name="CDP_Type_Length")
s_random("test", min_length=0, max_length=1000, name="CDP_Type_ID")

s_initialize("Info_Field_Header")
s_binary("0000", name="Type")
s_binary("0000", name="Length")

class Fuzzer(object):
    def __init__(self):
        self.afl_block_list        = []
        self.afl_block_type        = ["\x00\x05", "\x00\x06", "\x00\x02", "\x00\x03", "\x00\x04", "\x00\x09", "\x00\x0b"]
        self.infoPayload           = None

        self.afl_block_list.append(ex_afl.AFL("CDP_ELA_Fuzzing_SoftwareVersion", "cdp_ela/SoftwareVersion"))
        self.afl_block_list.append(ex_afl.AFL("CDP_ELA_Fuzzing_Platform", "cdp_ela/Platform"))
        self.afl_block_list.append(ex_afl.AFL("CDP_ELA_Fuzzing_Addresses", "cdp_ela/Addresses"))
        self.afl_block_list.append(ex_afl.AFL("CDP_ELA_Fuzzing_PortID", "cdp_ela/PortID"))
        self.afl_block_list.append(ex_afl.AFL("CDP_ELA_Fuzzing_Capab", "cdp_ela/Capab"))
        self.afl_block_list.append(ex_afl.AFL("CDP_ELA_Fuzzing_VTP", "cdp_ela/VTP"))
        self.afl_block_list.append(ex_afl.AFL("CDP_ELA_Fuzzing_Duplex", "cdp_ela/Duplex"))

        for afl_block in self.afl_block_list:
            afl_block.start_afl_fuzz()

    def set_mutate_frame_callback(self):
        return "sulley"

    def post_mutate_callback(self, block):
        self.infoPayload              = ""
        self.infoFieldHeaderBlock     = s_get("Info_Field_Header")

        for idx in xrange(0, len(self.afl_block_list)):
            self.afl_block_list[idx].mutate()
            aflPayload = self.afl_block_list[idx].render()

            try:
                self.infoFieldHeaderBlock.set_field_value("Type", self.afl_block_type[idx])
                self.infoFieldHeaderBlock.set_field_value("Length", struct.pack(">H", len(aflPayload) + 4))
            except Exception, e:
                print "set_field_value() error. Exception: " + str(e)

            self.infoPayload += self.infoFieldHeaderBlock.render() + aflPayload

        idName = block.get_field_value("CDP_Type_ID")
        block.set_field_value("CDP_Type_Length", struct.pack(">H", len(idName) + 4))

        block.set_field_value("eth_length", struct.pack(">H", len(block.render()) + len(self.infoPayload) - 14))
        print "LLC Protocol Length: %d" % struct.unpack(">H", block.get_field_value("eth_length"))[0]
        block.set_field_value("CDP_Checksum", "\x00\x00")

    def pre_send_callback(self, sock, block, data):
        payload = data + self.infoPayload
        print "Eth Protocol Length: %d" % len(payload)
        cksum = None
        try:
            cksum = s_checksum(payload[22:], "ip", "<")
        except Exception, e:
            print "s_checksum failed. " + str(e)
            os._exit(0)

        try:
            block.set_field_value("CDP_Checksum", cksum)
        except Exception, e:
            print "set_field_value failed. " + str(e)
            os._exit(0)
        return block.render() + self.infoPayload

    def detected_target_crash_callback(self, fuzzStoreList):
        dump_fuzz_store_list("cdp_crash_2.txt", fuzzStoreList)
        return False

if __name__ == '__main__':
    fuzz = Fuzzer()
    sess = sessions.session(send_iface="ens38", proto="layer2", keep_alive=False, pinger_threshold=100, fuzz_store_limit=10000)

    sess.set_mutate_frame_callback        = fuzz.set_mutate_frame_callback
    sess.post_mutate_callback             = fuzz.post_mutate_callback
    sess.pre_send_callback                = fuzz.pre_send_callback
    sess.detected_target_crash_callback   = fuzz.detected_target_crash_callback

    target = sessions.target("10.0.0.1", 22)

    sess.add_block(s_get("Packet_Header"))
    sess.add_target(target)

    sess.fuzz()