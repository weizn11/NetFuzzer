# -*- coding:utf-8 -*-
import os
import sys
import getopt
import signal
import time
import threading
import select
import socket
import struct
import cPickle
from sulley.protocol import *

USAGE = "USAGE: process_monitor_unix.py"\
        "\n    [-p|--port PORT]             TCP port to bind this"\
        "\n    [-l|--log_level LEVEL]       log level (default 1), increase for more verbosity"

ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or os._exit(1)

servlet = None

class server:
    def __init__ (self, host, port):
        self._host           = host
        self._port           = port
        self._dbg_flag       = False
        self._client_sock    = None
        self._client_address = None

        try:
            # create a socket and bind to the specified port.
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.settimeout(None)
            self._server.bind((self._host, self._port))
            self._server.listen(1)
        except:
            sys.stderr.write("unable to bind to %s:%d\n" % (self._host, self._port))
            os._exit(1)


    ####################################################################################################################
    def _disconnect (self):
        '''
        Ensure the socket is torn down.
        '''

        if self._client_sock != None:
            self._debug("closing client socket")
            self._client_sock.close()
            self._client_sock = None


    ####################################################################################################################
    def _debug (self, msg):
        print "PED-RPC> %s" % msg


    ####################################################################################################################
    def _ex_recv (self):
        '''
        '''

        recvLength = 4
        nextLength = 0

        try:
            while recvLength:
                nextLength = self._client_sock.recv(recvLength)
                recvLength -= len(nextLength)
        except:
            print "recv() error at step 1"
            raise Exception

        recvLength = struct.unpack("<i", nextLength)[0]
        try:
            data = ""
            while recvLength:
                chunk = self._client_sock.recv(recvLength)
                data += chunk
                recvLength -= len(data)
        except:
            print "recv() error at step 2"
            raise Exception

        hdr = cPickle.loads(data)
        recvLength = hdr.nextLength
        try:
            data = ""
            while recvLength:
                chunk = self._client_sock.recv(recvLength)
                data += chunk
                recvLength -= len(data)
        except:
            print "recv() error at step 3"
            raise Exception

        objData = cPickle.loads(data)

        return objData


    ####################################################################################################################
    def _ex_send (self, data):
        '''
        @param data:
        @return:
        '''

        serData = cPickle.dumps(data,protocol=2)
        hdr = Header(nextProtoName=data.protoName,nextLength=len(serData))
        serHdr = cPickle.dumps(hdr,protocol=2)

        try:
            self._client_sock.send(struct.pack("<i",len(serHdr)))
            self._client_sock.send(serHdr)
            self._client_sock.send(serData)
        except:
            print "send error!"
            raise Exception

####################################################################################################################
class debugger_thread(threading.Thread):
    global servlet
    def __init__(self, procmon_options):
        super(debugger_thread,self).__init__()

        self.procmon_options = procmon_options
        self.pid = None
        self.readBuff = ""
        self.gdbActive = False
        self.c_str = self.procmon_options["crash_code"]    #出现此特征码则表明进程crash
        self.crash = False

        self.wrPipe = [0,0]
        self.rdPipe = [0,0]
        self.errPipe = [0,0]

        try:
            self.wrPipe[0],self.wrPipe[1] = os.pipe()
            self.rdPipe[0],self.rdPipe[1] = os.pipe()
            self.errPipe[0],self.errPipe[1] = os.pipe()
        except Exception ,e:
            print "Create pip failed.\nTrace info:"
            print e
            os._exit(0)
        
    def start_monitoring(self):
        '''
        @desc:  debugger子进程
        '''

        os.close(self.rdPipe[0])
        os.close(self.wrPipe[1])
        os.close(self.errPipe[0])

        #绑定管道
        os.dup2(self.rdPipe[1],sys.stdout.fileno())
        os.dup2(self.wrPipe[0],sys.stdin.fileno())
        os.dup2(self.errPipe[1],sys.stderr.fileno())

        #启动debugger
        args = self.procmon_options["cmdline"]
        args.insert(0, self.procmon_options["path"])
        os.execv(self.procmon_options["path"], args)

    def write_to_gdb(self,cmd=""):
        if len(cmd) > 0 and cmd[len(cmd)-1]!='\n':
            cmd += "\n"

        try:
            os.write(self.wrPipe[1],cmd)
        except Exception, e:
            print "write pipe failed.\nTrace info:"
            print e
            raise Exception

    def run(self):
        timestamp = time.time()
        self.pid = os.fork()
        if self.pid == 0:
            #debugger子进程
            self.start_monitoring()
            os._exit(0)

        os.close(self.wrPipe[0])
        os.close(self.rdPipe[1])
        os.close(self.errPipe[1])

        try:
            #debugger输入流配置的命令
            if len(self.procmon_options["stdin"]) > 0:
                for cmd in self.procmon_options["stdin"]:
                    self.write_to_gdb(cmd)

        except:
            print "Set debugger cmd failed"
            os._exit(0)

        while True:
            #从管道中读取debugger输出数据
            rdSet = [self.rdPipe[0],self.errPipe[0]]
            rdList, wrList, errList = select.select(rdSet,[],[],0.001)
            for r in rdList:
                if r is self.rdPipe[0]:
                    try:
                        #从管道中读取数据
                        self.readBuff = os.read(r,65536)
                        if len(self.readBuff) <= 0:
                            print "rd pipe read failed"
                            self.crash = True
                            servlet.report_crash("rd pipe read failed")
                            servlet.report_EOF = True
                            time.sleep(10)
                            continue
                        print self.readBuff
                        servlet.stdoutInfo = self.readBuff

                        if not self.crash and self.gdbActive:
                            #从读取的数据中检查进程是否crash
                            if self.procmon_options["match_logic"] == 1:
                                for str in self.c_str:
                                    try:
                                        self.readBuff.index(str)
                                    except:
                                        #抛出异常则表明进程未crash
                                        self.crash = False
                                        break
                                    self.crash = True
                            else:
                                for str in self.c_str:
                                    try:
                                        self.readBuff.index(str)
                                    except:
                                        #抛出异常则表明进程未crash
                                        continue
                                    self.crash = True
                                    break

                            #当进程发生crash，向debugger中写入读取crash信息的命令
                            if self.crash:
                                for cmd in self.procmon_options["crash_cmd"]:
                                    self.write_to_gdb(cmd)

                        if self.crash:
                            #收集crash信息
                            servlet.report_crash(self.readBuff)
                            timestamp = time.time()

                    except Exception, e:
                        print "pipe read exception.\nTrace info:"
                        print e
                        self.crash = True
                        servlet.report_crash("rd pipe read failed")
                        servlet.report_EOF = True
                        time.sleep(10)
                        continue

                elif r is self.errPipe[0]:
                    try:
                        self.readBuff = os.read(r, 1024)
                        if len(self.readBuff) <= 0:
                            continue

                        print self.readBuff
                    except:
                        continue

            #若进程已崩溃，并超过2秒没再收到crash信息，则向Fuzzer返回crash报告。
            if self.crash and (time.time() - timestamp > 2):
                servlet.report_EOF = True

########################################################################################################################

class nix_process_monitor_pedrpc_server(server):
    def __init__(self, host, port, log_level=1):
        '''
        @type host: String
        @param host: Hostname or IP address
        @type port: Integer
        @param port: Port to bind server to
        '''
        
        server.__init__(self, host, port)
        self.log_level = log_level
        self.dbg = None
        self.log("Process Monitor PED-RPC server initialized:")
        self.log("Listening on %s:%s" % (host, port))
        self.log("awaiting requests...")
        self.recvData = None
        self.procmon_options = {}
        self.debug_thread = None
        self.thread_start = False

        self.report_EOF = False
        self.crashReport = ""
        self.stdoutInfo = None

    ####################################################################################################################
    def report_crash(self,report):
        self.crashReport += report

    def serve_forever (self):
        while 1:
            #监听并接受一个连接
            try:
                self._disconnect()
                (self._client_sock, self._client_address) = self._server.accept()
                self._debug("accepted connection from %s:%d" % (self._client_address[0], self._client_address[1]))
            except:
                print "accept socket failed"
                continue

            #循环处理命令
            while True:
                self.recvData = None
                #从Fuzzer接收数据
                try:
                    self.recvData = self._ex_recv()
                    #print "recv proto:",self.recvData.protoName
                except:
                    print "recv exception"
                    os._exit(0)

                #协议处理
                if self.recvData.protoName == "Debug_Options":
                    try:
                        self.procmon_options = self.recvData.procmonOptions
                        #print self.procmon_options
                        self.debug_thread = debugger_thread(self.procmon_options)   #create debug thread class
                    except:
                        print "create debug object exception"
                        os._exit(0)

                elif self.recvData.protoName == "Debug_Report":
                    pass

                elif self.recvData.protoName == "Debug_Cmd":
                    if self.recvData.cmd == "start":
                        try:
                            self.debug_thread.start()
                        except:
                            print "create debug thread exception"
                            os._exit(0)

                        try:
                            time.sleep(1)
                            self.debug_thread.write_to_gdb("r\n")
                            self.debug_thread.gdbActive = True
                        except:
                            print "write to gdb exception"
                            os._exit(0)
                        self.thread_start = True

                #Fuzzer询问进程是否crash
                elif self.recvData.protoName == "Fetch_Report":
                    #等待进程反应时间。
                    time.sleep(self.procmon_options["continue_spacing"])

                    #回送报告
                    if self.debug_thread.crash:
                        while not self.report_EOF:
                            time.sleep(0.1)
                        debugReport = Debug_Report(crash=True, report=self.crashReport)
                        self._ex_send(debugReport)
                        os._exit(0)
                    else:
                        debugReport = Debug_Report(crash=False, report=self.stdoutInfo)
                        self._ex_send(debugReport)


    def log (self, msg="", level=1):
        '''
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: String
        @param msg: Message to log
        '''

        if self.log_level >= level:
            print "[%s] %s" % (time.strftime("%I:%M.%S"), msg)
    
########################################################################################################################

def sigint_handler(sig, frame):
    print "recv sigint"
    os._exit(0)

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:l:", ["port=","log_level=",])
    except getopt.GetoptError:
        ERR(USAGE)

    log_level = 1
    PORT = None
    for opt, arg in opts:
        if opt in ("-p", "--port"): PORT = int(arg)
        if opt in ("-l", "--log_level"):   log_level  = int(arg)
    
    if PORT == None:
        PORT = 7437
    signal.signal(signal.SIGINT,sigint_handler)

    servlet = nix_process_monitor_pedrpc_server("0.0.0.0", PORT, log_level)
    #启动监听
    servlet.serve_forever()

