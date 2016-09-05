from sulley import *

s_initialize("arp")

s_binary("0xff ff ff ff ff ff")
s_binary("0x01 02 03 04 05 06")
s_binary("0x08 06")

s_binary("0x00 01") #/* Hardware Type -> here Ethernet (1)*/
s_binary("0x08 00") #/* Protocol Type -> here IP (8) */
s_binary("0x06") #/* Hardware size -> here MAC (48Bit /6Byte) */
s_binary("0x04") #/* Protocol Size -> here IP (32Bit /4Byte) */
s_binary("0x00 01") #/* Opcode (1->request, 2->reply) */
s_binary("0x01 02 03 04 05 06") #/* MAC-Src */
s_binary("0xc0 a8 5f b5") #/* IP-Src */
s_binary("0x00 00 00 00 00 00") #/* MAC-Dst */
s_binary("0xc0 a8 5f b6") #/* IP-Dst */
s_random(0x0000, 1, 50,num_mutations=100000)

sess = sessions.session(proto="layer2", send_iface="eth0",sleep_time=0)
sess.add_block(s_get("arp"))

target = sessions.target("layer2", 1234)
sess.add_target(target)

sess.fuzz()
