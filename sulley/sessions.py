# -*- coding:utf-8 -*-
import os
import sys
import time
import socket

# Use libdnet for layer2 support
import dnet

import logging
import sex
import primitives
import SniffThread
import protocol
import signal

########################################################################################################################
class target:
    '''
    Target descriptor container.
    '''

    def __init__ (self, host, port):
        '''
        @type  host: String
        @param host: Fuzz目标地址
        @type  port: Integer
        @param port: Fuzz目标端口
        '''

        #Fuzz目标地址
        self.host      = host
        self.port      = port

        #进程监视器
        self.procmon           = None   #type : pedrpc.client()
        self.procmon_options   = {}
        #进程监视器连接标识
        self.connFlag = False
        #进程监视器启动标识
        self.startFlag = False
        #进程监视器Socket
        self.procmonSocket = None
        '''
        procmon_options =
        {
            "path" : "",                #debugger文件路径
            "cmdline" : [],             #debug的文件，可为空
            "stdin" : [],               #debugger从输入流中传入的命令
            "crash_cmd" : [],           #发生crash后，debugger获取crash信息命令
            "continue_spacing" : 1,     #等待进程反应时间
            "crash_code" : [],          #发生crash的特征码
            "match_logic" : 1           #匹配逻辑 1:与 0:或
        }
        '''

    def procmon_connect (self):
        '''
        @desc:  connect to proc monitor
        '''

        if self.procmon and not self.connFlag:
            debugOptions = protocol.Debug_Options(self.procmon_options)
            #连接到进程监视器
            self.procmon.connect()
            #发送Debug参数
            self.procmon.ex_send(debugOptions)

    def procmon_start(self):
        if not self.procmon or self.startFlag:
            return
        #启动进程监视器
        debugCmd = protocol.Debug_Cmd("start")
        self.procmon.ex_send(debugCmd)



########################################################################################################################

class custom_sock():
    def __init__(self,target, ex_send_callback):
        self.ex_send_callback = ex_send_callback
        self.target = target

        if ex_send_callback is None:
            print "ex_send_callback not set"
            raise Exception

    def send(self,data):
        #自定义发送函数
        self.ex_send_callback(self.target, data)

    def close(self):
        pass

########################################################################################################################
class session ():
    def __init__(
                  self,
                  loop_sleep_time=0.0,      #每次循环fuzz的时间间隔
                  proto="tcp",              #使用的连接协议
                  sock_timeout=5.0,         #socket超时时间
                  send_iface="eth0",        #发送数据包使用的网卡
                  sniff_iface="eth0",      #进行网络监听的网卡
                  sniff_stop_filter=None,   #设置网络监视器的stop_filter
                  sniff_timout=None,        #网络监视器超时间隔
                  sniff_switch=False,       #是否启动网络监视器
                  sniff_filter="",          #设置数据包过滤
                  keep_alive=False,         #是否保持socket连接
                  send_sleep_time=0.0       #发送每个测试用例的时间间隔
                ):

        log_level=logging.INFO
        logfile=None
        logfile_level=logging.DEBUG

        self.loop_sleep_time          = loop_sleep_time
        self.send_sleep_time          = send_sleep_time
        self.proto               = proto.lower()
        self.ssl                 = False
        self.timeout             = sock_timeout
        self.total_mutant_index  = 0
        self.fuzz_targets        = []
        self.fuzz_blocks         = []
        self.procmon_results     = {}
        self.protmon_results     = {}
        self.pause_flag          = False
        self.crashing_primitives = {}
        self.keep_alive          = keep_alive

        self.layer2              = False
        self.custom              = False
        self.iface               = send_iface

        self.message             = ''
        self.sniff_iface              = sniff_iface
        self.sniff_thread         = None
        self.sniff_switch = sniff_switch
        self.sniff_filter = sniff_filter
        self.sniff_stop_filter = sniff_stop_filter
        self.sniff_timeout = sniff_timout

        #创建网络监视器
        if self.sniff_switch:
            try:
                self.sniff_thread = SniffThread.Sniffer(self.sniff_iface,self.sniff_filter,self.sniff_stop_filter,self.sniff_timeout)
            except Exception, e:
                print "sniff thread create failed.\nTrace info:"
                print e
                os._exit(0)

        #初始化日志
        self.logger = logging.getLogger("NetFuzzer_logger")
        self.logger.setLevel(log_level)
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] -> %(message)s')

        if logfile != None:
            filehandler = logging.FileHandler(logfile)
            filehandler.setLevel(logfile_level)
            filehandler.setFormatter(formatter)
            self.logger.addHandler(filehandler)

        consolehandler = logging.StreamHandler()
        consolehandler.setFormatter(formatter)
        consolehandler.setLevel(log_level)
        self.logger.addHandler(consolehandler)

        #判断用户使用的连接协议
        if self.proto == "tcp":
            self.proto = socket.SOCK_STREAM

        elif self.proto == "ssl":
            self.proto = socket.SOCK_STREAM
            self.ssl   = True

        elif self.proto == "udp":
            self.proto = socket.SOCK_DGRAM

        elif self.proto == "layer2":
           self.layer2 = True

        elif self.proto == "custom":
            self.custom = True

        else:
            raise sex.SullyRuntimeError("INVALID PROTOCOL SPECIFIED: %s" % self.proto)


    ####################################################################################################################
    def add_block (self, block):
        self.fuzz_blocks.append(block)

        return self

    ####################################################################################################################
    def add_target (self, target):
        '''
        @type  target: session.target()
        @param target: Target to add to session
        '''

        #连接到进程监视器
        target.procmon_connect()

        #将fuzz目标添加到会话列表中
        self.fuzz_targets.append(target)

    ####################################################################################################################
    def connect_failed_callback(self, sock, target):
        '''
        @type socket
        @param sock:    连接目标的socket
        @type session.target()
        @param target:  Fuzz目标
        @return: (boolean) 1.True:重新连接 2.退出程序
        '''
        return False

    def send_failed_callback(self, target, data):
        '''
        @type: sessions.target()
        @param target: Fuzz目标
        @type: String
        @param data: 生成好的测试用例
        @return: True:重新进行连接  False:退出程序
        '''

        return False

    def block_mutate_callback(self, block):
        '''
        @type: blocks.request()
        @param block: 新生成的测试用例
        @return: 无返回值
        '''
        pass

    def start_wait_callback(self):
        pass

    def fetch_proc_crash_callback(self, report):
        '''
        @desc: 进程监视器已捕获到crash信息
        @type: String
        @param report: crash报告
        @return: (boolean)  1.True:继续进行接下来的流程 False:退出程序
        '''
        return False

    def ex_send_callback(self, target, data):
        '''
        @desc: 自定义数据包发送回调函数
        @type: sessions.target()
        @param target: Fuzz目标
        @type: String
        @param data: 生成好的测试用例
        @return: 无返回值
        '''
        pass

    def sigint_handler(sig, frame):
        print "recv sigint"
        os._exit(0)

    def fuzz (self):
        '''
        '''

        reconn = False
        againMutate = False
        data = None
        sock = None
        blockIndex = 0
        newMutant = True

        f_target = self.fuzz_targets[0]

        signal.signal(signal.SIGINT, self.sigint_handler)

        #启动网络监视器
        if self.sniff_switch:
            try:
                self.sniff_thread.packet_handler_callback = self.packet_handler_callback
                self.sniff_thread.start()
                time.sleep(0.1)
            except Exception, e:
                print "sniff thread start error.\nTrace info:"
                print e
                #os._exit(0)
            print "sniff thread start."

        #启动进程监视器
        f_target.procmon_start()

        self.start_wait_callback()
        print "Press CTRL/C to cancel in ",
        for i in range(3):
            print str(3 - i) + " ",
            sys.stdout.flush()
            time.sleep(1)
        print "\nFuzzing...\n"

        done_with_fuzz_node = False

        # loop through all possible mutations of the fuzz block.
        while not done_with_fuzz_node:
            if blockIndex >= len(self.fuzz_blocks):
                blockIndex = 0

            if newMutant:
                self.total_mutant_index += 1
                self.logger.info("fuzzing %d" % (self.total_mutant_index))
                newMutant = False

            #从数据结构列表中取出一个进行测试
            f_block = self.fuzz_blocks[blockIndex]

            #生成测试数据
            if not f_block.mutate():
                self.logger.error("all possible mutations for current fuzz node exhausted")
                if self.total_mutant_index >= self.total_num_mutations:
                    #已用尽所有的测试用例
                    done_with_fuzz_node = True
                    continue
            else:
                #成功获取到新的测试用例
                try:
                    self.block_mutate_callback(f_block)
                except Exception, e:
                    print "block_mutate_callback() Exception.\nTrace info:"
                    print e
                    raise Exception

            def error_handler (e, msg, sock=None):
                if not self.layer2 and not self.custom and sock:
                    sock.close()
                self.logger.critical(msg)

            while 1:
                #判断连接协议并创建连接
                if self.layer2:
                    sock = dnet.eth(self.iface) #create eth class

                elif self.custom:
                    #用户自定义协议类型
                    sock = custom_sock(f_target, self.ex_send_callback)

                else:  #TCP or UDP
                    if not sock or not self.keep_alive:
                        #创建socket
                        try:
                            (family, socktype, proto, canonname, sockaddr)=socket.getaddrinfo(f_target.host, f_target.port)[0]
                            sock = socket.socket(family, self.proto)
                        except Exception, e:
                            error_handler(e, "failed creating socket", sock)
                            sock = None
                            continue

                        #连接到fuzz目标
                        try:
                            sock.settimeout(self.timeout)
                            # Connect is needed only for TCP stream
                            if self.proto == socket.SOCK_STREAM:
                                sock.connect((f_target.host, f_target.port))
                        except Exception, e:
                            error_handler(e, "failed connecting on socket", sock)
                            sock = None
                            try:
                                reconn = self.connect_failed_callback(sock, f_target)
                                if not reconn:
                                    os._exit(0)
                            except Exception, e:
                                print "connect_failed_callback() exception.\nTrace info:"
                                print e
                            continue

                #向目标发送生成好的测试用例
                try:
                    (reconn, normal, againMutate) = self.transmit(sock, f_block, f_target, data)  #send fuzzing packet
                    data = None
                    if reconn and sock:
                        sock.close()
                        sock = None
                    elif not normal and not reconn:
                        print "disconnect!"
                        os._exit(0)
                except Exception, e:
                    error_handler(e, "failed transmitting fuzz block", sock)
                    sock = None
                    continue
                break  #don't need resend

            # done with the socket.
            if not self.layer2 and not sock and not self.keep_alive:
                sock.close()
                sock = None

            if not againMutate:
                blockIndex += 1

            #输出日志
            if blockIndex >= len(self.fuzz_blocks):
                self.logger.info("sleeping for %f seconds\n-------------------------------------------------" % self.loop_sleep_time)
                time.sleep(self.loop_sleep_time)
                newMutant = True
            elif self.send_sleep_time <> 0:
                self.logger.info("sleeping for %f seconds\n-------------------------------------------------" % self.send_sleep_time)
                time.sleep(self.send_sleep_time)

    ####################################################################################################################
    def post_send_callback(self, sock, data):
        '''
        @type:  Socket
        @param sock: 连接到Fuzz目标的Socket
        @type:  String
        @param data: 生成好的测试用例
        @return: (boolean, boolean) 1.True: 重新发送此数据包 False:不用重新发送  2.True: 用新的测试用例再次测试此步骤 False:不用再做此步骤测试
        '''
        return (False, False)

    def post_send (self, sock, data):
        '''
        @type:  Socket
        @param sock: 连接到Fuzz目标的Socket
        @type:  String
        @param data: 生成好的测试用例
        @return: (boolean, boolean) 1.True: 重新发送此数据包 False:不用重新发送  2.True: 用新的测试用例再次测试此步骤 False:不用再做此步骤测试
        '''

        (resend, againMutate) = self.post_send_callback(sock, data)

        return (resend, againMutate)


    ####################################################################################################################
    def packet_handler_callback(self, pkt):
        '''
        @type: Packet
        @param pkt: 通过Scapy sniff()函数抓取的数据包
        @return: 无返回值
        '''
        pass

    def pre_send_callback(self, sock, block, data):
        '''
        @type: Socket
        @param sock: 连接到Fuzz目标的Socket
        @type: blocks.request()
        @param block: 当前Fuzz的数据结构
        @type: String
        @param _data: 生成好的测试用例
        @type: String
        @return: 返回修改后的发送数据包
        '''

        return data

    def pre_send (self, sock, block, _data):
        '''
        @type: Socket
        @param sock: 连接到Fuzz目标的Socket
        @type: blocks.request()
        @param block: 当前Fuzz的数据结构
        @type: String
        @param _data: 生成好的测试用例
        @type: String
        @return: 返回修改后的发送数据包
        '''

        data = self.pre_send_callback(sock, block, _data)

        return data

    ####################################################################################################################
    def transmit (self, sock, block, target, _data=None):
        sendFlag = True
        againMutate = False
        reconn = False
        normal = True

        #若没有传入指定的发送数据，则从block中生成发送数据。
        try:
            if not _data:
                data = block.render()    #generate fuzzing data
            else:
                data = _data
        except Exception, e:
            print "generate fuzzing data error.\nTrace info:"
            print e
            return

        while sendFlag:
            sendFlag = False

            #如果UDP数据包大于65507，则进行截断。
            if self.proto == socket.SOCK_DGRAM:
                MAX_UDP = 65507

                if os.name != "nt" and os.uname()[0] == "Darwin":
                    MAX_UDP = 9216

                if len(data) > MAX_UDP:
                    self.logger.debug("Too much data for UDP, truncating to %d bytes" % MAX_UDP)
                    data = data[:MAX_UDP]

            #发送前的回调函数，返回修改后的测试数据。
            try:
                data = self.pre_send(sock, block, data)
            except Exception, e:
                print "pre_send_callback() exception.\nTrace info:"
                print e
                raise Exception

            #开始发送测试数据包
            if self.layer2:   #layer2
                try:
                    sock.send(data)
                except Exception, inst:
                    self.logger.error("Socket error, send: %s" % inst)
                    try:
                        #发送失败的回调函数，返回重连标识。
                        reconn = self.send_failed_callback(target, data)
                        normal = False
                    except Exception, e:
                        print "send_failed_callback() error.\nTrace info:"
                        print e
                        raise Exception

            elif self.custom:   #自定义发送函数
                try:
                    sock.send(data)
                except Exception, e:
                    self.logger.error("custom send exception.\nTrace info:")
                    print e
                    try:
                        #发送失败的回调函数，返回重连标识。
                        reconn = self.send_failed_callback(target, data)
                        normal = False
                    except Exception, e:
                        print "send_failed_callback() error.\nTrace info:"
                        print e
                        raise Exception
            else:   #TCP or UDP
                try:
                    if self.proto == socket.SOCK_STREAM:
                        sock.send(data)
                    else:
                        sock.sendto(data, (target.host, target.port))
                except Exception, inst:
                    self.logger.error("Socket error, send: %s" % inst)
                    try:
                        #发送失败的回调函数，返回重连标识。
                        reconn = self.send_failed_callback(target, data)
                        normal = False
                    except Exception, e:
                        print "send_failed_callback() error.\nTrace info:"
                        print e
                        raise Exception

            #从进程监视器中获取进程信息
            if target.procmon:
                try:
                    crash, report = target.procmon.fetch_procmon_status()
                except Exception, e:
                    print "fetch_procmon_status() error.\nTrace info:"
                    print e
                    os._exit(0)
                    raise Exception
                if crash:
                    #测试用例造成进程crash，调用crash回调函数，传入crash报告。
                    try:
                        if not self.fetch_proc_crash_callback(report):
                            print "Fuzzing complete."
                            os._exit(0)
                    except Exception, e:
                        print "fetch_proc_crash_callback() exception.\nTrace info:"
                        print e
                    #print report
                    #print "crash data:",binascii.b2a_hex(data)
                    #os._exit(0)

            #发送结束后的回调函数
            if normal:
                try:
                    #返回重发和重新对此步骤生成测试用例的标识。
                    (sendFlag, againMutate) = self.post_send(sock, data)
                except Exception, e:
                    print "post_send() error.\nTrace info:"
                    print e
                    raise Exception

        return (reconn, normal, againMutate)
########################################################################################################################

