# -*- coding:utf-8 -*-
import os
import sys
import time
import socket

# Use libdnet for layer2 support
import dnet

import logging
import sex
import ping
import SniffThread
import protocol
import signal
import port_scanner

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
        self.host        = host
        self.port        = port

        self.pinger      = ping.Pinger(self.host)
        self.tcpScanner  = port_scanner.TCPScanner(self.host, self.port)
        self.udpScanner  = port_scanner.UDPScaner(self.host, self.port)

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
            "cmdline" : [],             #命令行参数，可为空
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

    def detect_crash_via_ping(self):
        for idx in range(0, 7):
            if self.pinger.ping() is None:
                continue
            else:
                return False
        return True

    def detect_crash_via_tcp_port(self):
        if self.tcpScanner.scan():
            return False
        return True

    def detect_crash_via_udp_port(self):
        if self.udpScanner.scan():
            return False
        return True

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
                  sock_timeout=None,        #socket超时时间
                  send_iface="eth0",        #发送数据包使用的网卡
                  sniff_iface="eth0",       #进行网络监听的网卡
                  sniff_stop_filter=None,   #设置网络监视器的stop_filter
                  sniff_timout=None,        #网络监视器超时间隔
                  sniff_switch=False,       #是否启动网络监视器
                  sniff_filter="",          #设置数据包过滤
                  keep_alive=False,         #是否保持socket连接
                  send_sleep_time=0.0,      #发送每个测试用例的时间间隔
                  fuzz_store_limit=None,    #存储生成的fuzz数据最大数量
                  pinger_threshold=None,    #是否开启ping检测crash
                  tcpScan_threshold=None,   #是否开启tcp scan检测crash
                  udpScan_threshold=None,   #是否开启udp scan检测crash
                  cusDect_threshold=None,   #是否开启自定义callback函数检测crash
                  procDect_threshold=None   #是否开启procmon检测crash
                ):

        log_level=logging.INFO
        logfile=None
        logfile_level=logging.DEBUG

        self.loop_sleep_time     = loop_sleep_time
        self.send_sleep_time     = send_sleep_time
        self.proto               = proto.lower()
        self.timeout             = sock_timeout
        self.total_mutant_index  = 0
        self.fuzz_targets        = []
        self.fuzz_blocks         = []
        self.afl_fuzz_blocks     = []
        self.procmon_results     = {}
        self.protmon_results     = {}
        self.pause_flag          = False
        self.crashing_primitives = {}
        self.keep_alive          = keep_alive

        self.layer2              = False
        self.custom              = False
        self.iface               = send_iface

        self.message             = ''
        self.sniff_iface         = sniff_iface
        self.sniff_thread        = None
        self.sniff_switch        = sniff_switch
        self.sniff_filter        = sniff_filter
        self.sniff_stop_filter   = sniff_stop_filter
        self.sniff_timeout       = sniff_timout

        self.cur_mutate_frame    = None
        self.fuzz_store_list     = []
        self.fuzz_store_limit    = fuzz_store_limit
        self.fuzz_send_count     = 0

        self.pinger_threshold    = pinger_threshold
        self.tcpScan_threshold   = tcpScan_threshold
        self.udpScan_threshold   = udpScan_threshold
        self.cusDect_threshold   = cusDect_threshold
        self.procDect_threshold  = procDect_threshold

        #创建网络监视器
        if self.sniff_switch:
            try:
                self.sniff_thread = SniffThread.Sniffer(self.sniff_iface,self.sniff_filter,self.sniff_stop_filter,self.sniff_timeout)
            except Exception, e:
                print "sniff thread create failed. Exception: %s" % str(e)
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
        return

    ####################################################################################################################
    def add_afl_block(self, block):
        self.afl_fuzz_blocks.append(block)
        return

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
        print "Connect failed."
        return True

    def connect_success_callback(self, sock, target):
        '''
        @type socket
        @param sock:    连接目标的socket
        @type session.target()
        @param target:  Fuzz目标
        @return: (boolean) 1.True:重新连接 2.继续接下来的流程
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
        print "Send failed."
        return True

    def set_mutate_frame_callback(self):
        '''
        @return: 将要使用的数据生成框架
        '''
        return "sulley"

    def pre_mutate_callback(self, block):
        '''
        @param block: 新生成的测试用例
        @return: None
        '''
        pass

    def post_mutate_callback(self, block):
        '''
        @type: blocks.request()
        @param block: 新生成的测试用例
        @return: 无返回值
        '''
        pass

    def start_wait_callback(self):
        pass

    def fetch_proc_crash_callback(self, report, fuzzStoreList):
        '''
        @desc: 进程监视器已捕获到crash信息
        @type: String
        @param report: crash报告
        @type: list
        @param fuzzStoreList: 存储的fuzz数据
        @return: (boolean)  1.True:继续进行接下来的流程 False:退出程序
        '''
        return False

    def detected_target_crash_callback(self, fuzzStoreList):
        '''
        @desc: Net monitor已捕获到crash信息
        @type: list
        @param fuzzStoreList: 存储的fuzz数据
        @return: (boolean)  1.True:继续进行接下来的流程 False:退出程序
        '''
        return False

    def custom_detect_crash_callback(self, sock, target):
        '''
        @type socket
        @param sock:    连接目标的socket
        @type session.target()
        @param target:  Fuzz目标
        @return: (boolean) 1.True:检测到目标crash 2.False:目标未crash
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

    def sigint_handler(self, sig, frame):
        print ""
        self.logger.info("Recv sigint signal, the process will exit.")
        os._exit(0)

    def fuzz (self):
        reconn = False
        againMutate = False
        data = None
        sock = None
        blockIndex = 0
        aflBlockIndex = 0
        newMutant = True

        f_target = self.fuzz_targets[0]
        signal.signal(signal.SIGINT, self.sigint_handler)

        print "Press CTRL/C to cancel in ",
        for i in range(3):
            print str(3 - i) + " ",
            sys.stdout.flush()
            time.sleep(1)
        print "\n"

        #启动网络监视器
        if self.sniff_switch:
            try:
                self.sniff_thread.packet_handler_callback = self.packet_handler_callback
                self.sniff_thread.start()
                time.sleep(0.1)
            except Exception, e:
                self.logger.critical("Sniff thread start error. Exception: %s" % str(e))
                os._exit(0)
            self.logger.info("Sniff thread start.")

        #启动进程监视器
        if self.procDect_threshold is not None:
            f_target.procmon_start()

        self.logger.info("Wait for start...")
        self.start_wait_callback()
        self.logger.info("Start fuzzing...")

        # loop through all possible mutations of the fuzz block.
        while True:
            # 当前fuzz计数
            if newMutant:
                self.total_mutant_index += 1
                self.logger.info("Fuzzing %d" % (self.total_mutant_index))
                newMutant = False

            #指定fuzz数据生成框架
            try:
                self.cur_mutate_frame = self.set_mutate_frame_callback()
            except Exception, e:
                self.logger.critical("set_mutate_frame_callback() error. Exception: %s" % str(e))
                os._exit(-1)
            if self.cur_mutate_frame not in ("sulley", "afl"):
                self.logger.critical("cur_mutate_frame does not seem to be valid. value: %s" % self.cur_mutate_frame)
                raise Exception("[ERROR] cur_mutate_frame does not seem to be valid. value: %s" % self.cur_mutate_frame)

            #检测索引越界
            if self.cur_mutate_frame == "sulley":
                if blockIndex >= len(self.fuzz_blocks):
                    blockIndex = 0
            else:
                if aflBlockIndex >= len(self.afl_fuzz_blocks):
                    aflBlockIndex = 0

            #从数据列表中取出一个进行测试
            if self.cur_mutate_frame == "sulley":
                f_block = self.fuzz_blocks[blockIndex]
            else:
                f_block = self.afl_fuzz_blocks[aflBlockIndex]

            #设置block
            try:
                self.pre_mutate_callback(f_block)
            except Exception, e:
                self.logger.critical("pre_mutate_callback() error. Exception: %s" % str(e))
                os._exit(-1)

            #生成测试数据
            try:
                if not f_block.mutate():
                    self.logger.critical("all possible mutations for current fuzz node exhausted")
                    os._exit(-1)
            except Exception, e:
                self.logger.critical("Block mutate error. Exception: %s" % str(e))
                os._exit(-1)

            #成功获取到新的测试用例
            try:
                self.post_mutate_callback(f_block)
            except Exception, e:
                self.logger.critical("post_mutate_callback() error. Exception: %s" % str(e))
                os._exit(-1)

            def error_handler (e, msg, sock=None):
                if not self.layer2 and not self.custom and sock:
                    sock.close()
                self.logger.critical(msg + " Exception: %s" % str(e))

            while True:
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
                            (family, socktype, proto, canonname, sockaddr) = \
                                socket.getaddrinfo(f_target.host, f_target.port)[0]
                            sock = socket.socket(family, self.proto)
                        except Exception, e:
                            error_handler(e, "failed creating socket.", sock)
                            sock = None
                            continue

                        #连接到fuzz目标
                        try:
                            sock.settimeout(self.timeout)
                            # Connect is needed only for TCP stream
                            if self.proto == socket.SOCK_STREAM:
                                sock.connect((f_target.host, f_target.port))
                            sock.settimeout(None)
                            if self.connect_success_callback(sock, f_target):
                                sock.close()
                                sock = None
                                continue
                        except Exception, e:
                            error_handler(e, "failed connecting on socket.", sock)
                            sock = None
                            try:
                                # 立刻测试目标设备是否crash
                                self.detect_crash(sock, f_target, True)
                                reconn = self.connect_failed_callback(sock, f_target)
                                if not reconn:
                                    os._exit(0)
                            except Exception, e:
                                self.logger.critical("connect_failed_callback() error. Exception: %s" % str(e))
                            continue
                    else:
                        sock.settimeout(None)

                #向目标发送生成好的测试用例
                try:
                    (reconn, normal, againMutate) = self.transmit(sock, f_block, f_target, data)  #send fuzzing packet
                    data = None
                    if self.layer2 is False and self.custom is False:
                        if normal is False:
                            sock.close()
                            sock = None
                        if reconn and sock is not None:
                            sock.close()
                            sock = None
                    if normal is False and reconn is False:
                        self.logger.info("disconnect!")
                        os._exit(0)
                except Exception, e:
                    error_handler(e, "failed transmitting fuzz block.", sock)
                    sock = None
                    continue
                if reconn is False:
                    break  #don't need resend

            # done with the socket.
            if self.layer2 is False and self.custom is False and sock is not None and self.keep_alive is False:
                sock.close()
                sock = None

            if againMutate is False:
                if self.cur_mutate_frame == "sulley":
                    blockIndex += 1
                else:
                    aflBlockIndex += 1

            #输出日志
            if blockIndex >= len(self.fuzz_blocks):
                self.logger.info("sleeping for %f seconds\n-------------------------------------------------" %
                                 self.loop_sleep_time)
                time.sleep(self.loop_sleep_time)
                newMutant = True
            elif self.send_sleep_time <> 0:
                self.logger.info("sleeping for %f seconds\n-------------------------------------------------" %
                                 self.send_sleep_time)
                time.sleep(self.send_sleep_time)

    ####################################################################################################################
    def post_send_callback(self, sock, data, fuzzStoreList):
        '''
        @type:  Socket
        @param sock: 连接到Fuzz目标的Socket
        @type:  String
        @param data: 生成好的测试用例
        @type: list
        @param fuzzStoreList: 存储的fuzz数据
        @return: (boolean, boolean) 1.True: 重新发送此数据包 False:不用重新发送  2.True: 用新的测试用例再次测试此步骤 False:不用再做此步骤测试
        '''
        return (False, False)

    def post_send(self, sock, data, fuzzStoreList):
        '''
        @type:  Socket
        @param sock: 连接到Fuzz目标的Socket
        @type:  String
        @param data: 生成好的测试用例
        @type: list
        @param fuzzStoreList: 存储的fuzz数据
        @return: (boolean, boolean) 1.True: 重新发送此数据包 False:不用重新发送  2.True: 用新的测试用例再次测试此步骤 False:不用再做此步骤测试
        '''
        (resend, againMutate) = self.post_send_callback(sock, data, fuzzStoreList)
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
    def detect_crash(self, sock, target, prom):
        '''
        :param target:
        :param prom: 立刻检测
        :return: 1.True:目标crash 2.False
        '''
        # 通过monitor测试目标设备是否crash
        if self.cusDect_threshold:
            if self.fuzz_send_count % self.cusDect_threshold == 0 or prom is True:
                if self.custom_detect_crash_callback(sock, target):
                    # 目标crash
                    if len(self.fuzz_store_list) > self.fuzz_store_limit:
                        self.fuzz_store_list = self.fuzz_store_list[len(self.fuzz_store_list) - self.fuzz_store_limit:]
                    if self.detected_target_crash_callback(self.fuzz_store_list) is False:
                        os._exit(0)
                    else:
                        return True

        if self.pinger_threshold:
            if self.fuzz_send_count % self.pinger_threshold == 0 or prom is True:
                if target.detect_crash_via_ping():
                    # 目标crash
                    if len(self.fuzz_store_list) > self.fuzz_store_limit:
                        self.fuzz_store_list = self.fuzz_store_list[len(self.fuzz_store_list) - self.fuzz_store_limit:]
                    if self.detected_target_crash_callback(self.fuzz_store_list) is False:
                        os._exit(0)
                    else:
                        return True

        if self.tcpScan_threshold:
            if self.fuzz_send_count % self.tcpScan_threshold == 0 or prom is True:
                if target.detect_crash_via_tcp_port():
                    # 目标crash
                    if len(self.fuzz_store_list) > self.fuzz_store_limit:
                        self.fuzz_store_list = self.fuzz_store_list[len(self.fuzz_store_list) - self.fuzz_store_limit:]
                    if self.detected_target_crash_callback(self.fuzz_store_list) is False:
                        os._exit(0)
                    else:
                        return True

        if self.udpScan_threshold:
            if self.fuzz_send_count % self.udpScan_threshold == 0 or prom is True:
                if target.detect_crash_via_udp_port():
                    # 目标crash
                    if len(self.fuzz_store_list) > self.fuzz_store_limit:
                        self.fuzz_store_list = self.fuzz_store_list[len(self.fuzz_store_list) - self.fuzz_store_limit:]
                    if self.detected_target_crash_callback(self.fuzz_store_list) is False:
                        os._exit(0)
                    else:
                        return True

        # 从进程监视器中获取进程信息
        if self.procDect_threshold and target.procmon:
            if self.fuzz_send_count % self.procDect_threshold == 0 or prom is True:
                crash  = False
                report = None
                try:
                    crash, report = target.procmon.fetch_procmon_status()
                except Exception, e:
                    self.logger.critical("fetch_procmon_status() error. Exception: %s" % str(e))
                    os._exit(0)
                if crash:
                    # 测试用例造成进程crash，调用crash回调函数，传入crash报告。
                    try:
                        if not self.fetch_proc_crash_callback(report, self.fuzz_store_list):
                            print "Fuzzing complete."
                            os._exit(0)
                    except Exception, e:
                        self.logger.critical("fetch_proc_crash_callback() error. Exception: %s" % str(e))

        return False

    ####################################################################################################################
    def transmit (self, sock, block, target, _data=None):
        sendFlag        = True
        againMutate     = False
        reconn          = False
        normal          = True

        #若没有传入指定的发送数据，则从block中生成发送数据。
        try:
            if not _data:
                data = block.render()    #generate fuzzing data
            else:
                data = _data
        except Exception, e:
            self.logger.error("Generate fuzzing data error. Exception: %s" % str(e))
            return

        while sendFlag:
            sendFlag = False
            normal = True
            againMutate = False
            reconn = False

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
                #立刻测试目标设备是否crash
                self.detect_crash(sock, target, True)
                self.logger.critical("pre_send_callback() error. Exception: %s" % str(e))
                raise e

            #存储fuzz数据
            if self.fuzz_store_limit is not None and self.fuzz_store_limit > 0:
                if len(self.fuzz_store_list) >= self.fuzz_store_limit + self.fuzz_store_limit / 3:
                    self.fuzz_store_list = self.fuzz_store_list[len(self.fuzz_store_list) - self.fuzz_store_limit:]
                self.fuzz_store_list.append(data)

            #发送fuzz数据包
            if self.layer2:   #layer2
                try:
                    sock.send(data)
                except Exception, inst:
                    normal = False
                    self.logger.error("Socket error, send: %s" % inst)
                    try:
                        # 立刻测试目标设备是否crash
                        self.detect_crash(sock, target, True)
                        #发送失败的回调函数，返回重连标识。
                        reconn = self.send_failed_callback(target, data)
                    except Exception, e:
                        self.logger.critical("send_failed_callback() error. Exception: %s" % str(e))
                        raise e
            elif self.custom:   #自定义发送函数
                try:
                    sock.send(data)
                except Exception, e:
                    normal = False
                    self.logger.critical("Custom send error. Exception: %s" % str(e))
                    try:
                        # 立刻测试目标设备是否crash
                        self.detect_crash(sock, target, True)
                        #发送失败的回调函数，返回重连标识。
                        reconn = self.send_failed_callback(target, data)
                    except Exception, e:
                        self.logger.critical("send_failed_callback() error. Exception: %s" % str(e))
                        raise e
            else:   #TCP or UDP
                try:
                    sock.settimeout(self.timeout)
                    if self.proto == socket.SOCK_STREAM:
                        sock.send(data)
                    else:
                        sock.sendto(data, (target.host, target.port))
                    sock.settimeout(None)
                except Exception, inst:
                    normal = False
                    sock.settimeout(None)
                    self.logger.critical("Send error. Exception: %s" % inst)
                    try:
                        # 立刻测试目标设备是否crash
                        self.detect_crash(sock, target, True)
                        #发送失败的回调函数，返回重连标识。
                        reconn = self.send_failed_callback(target, data)
                    except Exception, e:
                        self.logger.critical("send_failed_callback() error. Exception: %s" % str(e))
                        raise e

            self.fuzz_send_count += 1
            #通过monitor测试目标设备是否crash
            self.detect_crash(sock, target, False)

            #发送结束后的回调函数
            try:
                #返回重发和重新对此步骤生成测试用例的标识。
                (sendFlag, againMutate) = self.post_send(sock, data, self.fuzz_store_list)
            except Exception, e:
                self.logger.critical("post_send() error. Exception: %s" % str(e))
                # 立刻测试目标设备是否crash
                self.detect_crash(sock, target, True)

        return (reconn, normal, againMutate)

########################################################################################################################

