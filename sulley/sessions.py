import os
import re
import sys
import zlib
import time
import socket
import httplib
import cPickle
import threading
import BaseHTTPServer

# Use libdnet for layer2 support
import dnet

# Threads
import thread
import threading

import httplib
import logging

import blocks
import pedrpc
import pgraph
import sex
import primitives
import pcapy
import SniffThread
import binascii
import gc
import protocol


########################################################################################################################
class target:
    '''
    Target descriptor container.
    '''

    def __init__ (self, host, port):
        '''
        @type  host: String
        @param host: Hostname or IP address of target system
        @type  port: Integer
        @param port: Port of target service
        '''

        self.host      = host
        self.port      = port

        # set these manually once target is instantiated.
        self.procmon           = None
        self.procmon_options   = {}

        self.connFlag = False
        self.startFlag = False
        '''
        procmon_options = \
        {
            "gdb_path" : "",
            "debug_file" : "",
            "gdb_cmd" : [],
            "proc_args" : "",
            "crash_cmd" : []
            "wait_time" : 1
        }
        '''
        self.procmonSocket = None


    def procmon_connect (self):
        '''
        connect to proc monitor
        '''

        if self.procmon and not self.connFlag:
            debugOptions = protocol.Debug_Options(self.procmon_options)
            self.procmon.connect()
            self.procmon.ex_send(debugOptions)

    def procmon_start(self):
        if not self.procmon or self.startFlag:
            return
        debugCmd = protocol.Debug_Cmd("start")
        self.procmon.ex_send(debugCmd)



########################################################################################################################

class custom_sock():
    def __init__(self,target,ex_send_callback):
        self.ex_send_callback = ex_send_callback
        self.target = target

        if ex_send_callback is None:
            print "ex_send_callback not set"
            raise Exception

    def send(self,data):
        self.ex_send_callback(self.target,data)

    def close(self):
        pass

########################################################################################################################
class session ():
    def __init__(
                  self,
                  loop_sleep_time=1.0,
                  log_level=logging.INFO,
                  logfile=None,
                  logfile_level=logging.DEBUG,
                  proto="tcp",
                  restart_interval=0,
                  sock_timeout=5.0,
                  send_iface="eth0",
                  sniff_device="eth0",
                  sniff_stop_filter=None,
                  sniff_timout=None,
                  sniff_switch=False,
                  sniff_filter="",
                  keep_alive=False,
                  ex_send_callback = None,
                  send_sleep_time=0.0
                ):

        self.loop_sleep_time          = loop_sleep_time
        self.send_sleep_time          = send_sleep_time
        self.proto               = proto.lower()
        self.ssl                 = False
        self.restart_interval    = restart_interval
        self.timeout             = sock_timeout
        self.total_num_mutations = 0
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
        self.ex_send_callback    = ex_send_callback

        self.message             = ''
        self.device              = sniff_device
        self.sniff_thread         = None
        self.sniff_switch = sniff_switch
        self.sniff_filter = sniff_filter
        self.sniff_stop_filter = sniff_stop_filter
        self.sniff_timeout = sniff_timout

        if self.sniff_switch:
            try:
                self.sniff_thread = SniffThread.Sniffer(self.device,self.sniff_filter,self.sniff_stop_filter,self.sniff_timeout)
            except:
                print "sniff thread create failed"
                os._exit(0)

        # Initialize logger
        self.logger = logging.getLogger("Sulley_logger")
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
        @type  target: session.target
        @param target: Target to add to session
        '''

        target.procmon_connect()

        # add target to internal list.
        self.fuzz_targets.append(target)

    ####################################################################################################################
    def connect_failed_callback(self,sock,target):
        return (False,None)

    def send_failed_callback(self,target,data):
        '''

        @param target:
        @param data:
        @return: True:reconn  False:exit
        '''

        return False

    def block_mutate_callback(self,block):
        pass

    def start_wait_callback(self):
        print "wait for proc monitor start..."
        time.sleep(3)

    def fetch_proc_crash_callback(self,report):
        return False

    def fuzz (self):
        '''
        Call this routine to get the ball rolling. No arguments are necessary as they are both utilized internally
        during the recursive traversal of the session graph.

        @type  this_node: request (node)
        @param this_node: (Optional, def=None) Current node that is being fuzzed.
        @type  path:      List
        @param path:      (Optional, def=[]) Nodes along the path to the current one being fuzzed.
        '''

        reconn = False
        againMutate = False
        data = None
        sock = None
        blockIndex = 0
        newMutant = True

        f_target = self.fuzz_targets[0]

        self.total_num_mutations = primitives.gl_max_mutations

        if self.sniff_switch:
            try:
                self.sniff_thread.packet_handler_callback = self.packet_handler_callback
                self.sniff_thread.start()
                time.sleep(0.1)
            except:
                print "sniff thread start error"
                #os._exit(0)

            print "sniff thread start."

        f_target.procmon_start()    #start proc monitor

        self.start_wait_callback()

        done_with_fuzz_node = False

        # loop through all possible mutations of the fuzz block.
        while not done_with_fuzz_node:
            if blockIndex >= len(self.fuzz_blocks):
                blockIndex = 0

            if newMutant:
                self.total_mutant_index += 1
                self.logger.info("fuzzing %d of %d" % (self.total_mutant_index, self.total_num_mutations))
                newMutant = False

            f_block = self.fuzz_blocks[blockIndex]

            if not f_block.mutate():          #generate mutant data
                self.logger.error("all possible mutations for current fuzz node exhausted")
                if self.total_mutant_index >= self.total_num_mutations:
                    done_with_fuzz_node = True
                    continue
            else:
                try:
                    self.block_mutate_callback(f_block)
                except:
                    print "block_mutate_callback() Exception"
                    raise Exception

            def error_handler (e, msg, sock=None):
                if not self.layer2 and not self.custom and sock:
                    sock.close()
                self.logger.critical(msg)

            while 1:
                if self.layer2:
                    sock = dnet.eth(self.iface) #create eth class

                elif self.custom:
                    sock = custom_sock(f_target,self.ex_send_callback)

                else:  #TCP or UDP
                    if not sock or not self.keep_alive:
                        try:
                            (family, socktype, proto, canonname, sockaddr)=socket.getaddrinfo(f_target.host, f_target.port)[0]
                            sock = socket.socket(family, self.proto)
                        except Exception, e:
                            error_handler(e, "failed creating socket", sock)
                            sock = None
                            continue

                        #connect to target host
                        try:
                            sock.settimeout(self.timeout)
                            # Connect is needed only for TCP stream
                            if self.proto == socket.SOCK_STREAM:
                                sock.connect((f_target.host, f_target.port))
                        except Exception, e:
                            error_handler(e, "failed connecting on socket", sock)
                            sock = None
                            reconn = self.connect_failed_callback(sock,f_target)
                            if not reconn:
                                os._exit(0)
                            continue

                # now send the current node we are fuzzing.
                try:
                    (reconn,normal,againMutate) = self.transmit(sock, f_block, f_target,data)  #send fuzzing packet
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

            # delay in between test cases.
            if blockIndex >=len(self.fuzz_blocks):
                self.logger.info("sleeping for %f seconds\n-------------------------------------------------" % self.loop_sleep_time)
                time.sleep(self.loop_sleep_time)
                newMutant = True
            elif self.send_sleep_time <> 0:
                self.logger.info("sleeping for %f seconds\n-------------------------------------------------" % self.send_sleep_time)
                time.sleep(self.send_sleep_time)


    ####################################################################################################################
    ####################################################################################################################
    def post_send_callback(self,sock,data):
        return (False,False)

    def post_send (self, sock, data):
        '''
        Overload or replace this routine to specify actions to run after to each fuzz request. The order of events is
        as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to tear down the RPC request.

        @see: pre_send()

        @type  sock: Socket
        @param sock: Connected socket to target
        @return True:resend  or  False
        '''

        # default to doing nothing.
        (resend,againMutate) = self.post_send_callback(sock, data)

        return (resend,againMutate)


    ####################################################################################################################
    def packet_handler_callback(self,pkt):
        pass

    def pre_send_callback(self,sock,blockName,_data):
        data = _data
        return data

    def pre_send (self, sock,blockName,_data):
        '''
        Overload or replace this routine to specify actions to run prior to each fuzz request. The order of events is
        as follows::

            pre_send() - req - callback ... req - callback - post_send()

        When fuzzing RPC for example, register this method to establish the RPC bind.

        @see: pre_send()

        @type  sock: Socket
        @param sock: Connected socket to target
        '''

        # default to doing nothing.
        data = self.pre_send_callback(sock,blockName,_data)

        return data

    ####################################################################################################################
    def transmit (self, sock, block, target,_data=None):
        '''
        Render and transmit a node, process callbacks accordingly.

        @type  sock:   Socket
        @param sock:   Socket to transmit node on
        @type  node:   Request (Node)
        @param node:   Request/Node to transmit
        @type  edge:   Connection (pgraph.edge)
        @param edge:   Edge along the current fuzz path from "node" to next node.
        @type  target: session.target
        @param target: Target we are transmitting to
        '''

        sendFlag = True
        againMutate = False
        reconn = False
        normal = True

        # if no data was returned by the callback, render the node here.
        try:
            if not _data:
                data = block.render()    #generate fuzzing data
            else:
                data = _data
        except:
            print "generate fuzzing data error"
            return

        while sendFlag:
            sendFlag = False

            # if data length is > 65507 and proto is UDP, truncate it.
            # TODO: this logic does not prevent duplicate test cases, need to address this in the future.
            if self.proto == socket.SOCK_DGRAM:
                # max UDP packet size.
                # TODO: anyone know how to determine this value smarter?
                # - See http://stackoverflow.com/questions/25841/maximum-buffer-length-for-sendto to fix this
                MAX_UDP = 65507

                if os.name != "nt" and os.uname()[0] == "Darwin":
                    MAX_UDP = 9216

                if len(data) > MAX_UDP:
                    self.logger.debug("Too much data for UDP, truncating to %d bytes" % MAX_UDP)
                    data = data[:MAX_UDP]

            #send packet
            try:
                data = self.pre_send(sock,block.name,data)
            except:
                print "pre_send_callback() exception"
                raise Exception

            if self.layer2:   #layer2
                try:
                    sock.send(data)
                except Exception, inst:
                    self.logger.error("Socket error, send: %s" % inst)
                    try:
                        reconn = self.send_failed_callback(target,data)
                        normal = False
                    except:
                        print "send_failed_callback() error"
                        raise Exception

            elif self.custom:
                try:
                    sock.send(data)
                except:
                    self.logger.error("custom send error")
                    try:
                        reconn = self.send_failed_callback(target,data)
                        normal = False
                    except:
                        print "send_failed_callback() error"
                        raise Exception
            else:
                try:
                    if self.proto == socket.SOCK_STREAM:
                        sock.send(data)
                    else:
                        sock.sendto(data, (target.host, target.port))
                    #self.logger.debug("Packet sent : " + repr(data))
                except Exception, inst:
                    self.logger.error("Socket error, send: %s" % inst)
                    try:
                        reconn = self.send_failed_callback(target,data)
                        normal = False
                    except:
                        print "send_failed_callback() error"
                        raise Exception

            if target.procmon:
                try:
                    crash,report = target.procmon.fetch_procmon_status()
                except:
                    print "fetch_procmon_status() error"
                    raise Exception
                if crash:
                    if not self.fetch_proc_crash_callback(report):
                        print "Fuzzing complete."
                        os._exit(0)
                    #print report
                    #print "crash data:",binascii.b2a_hex(data)
                    #os._exit(0)

            if normal:
                try:
                    (sendFlag,againMutate) = self.post_send(sock,data)
                except:
                    print "post_send() error"
                    raise Exception

        return (reconn,normal,againMutate)
########################################################################################################################

