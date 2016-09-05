import os
import sys
import getopt
import signal
import time
import threading
import select
from sulley import pedrpc
from sulley import protocol

'''
'''

USAGE = "USAGE: process_monitor_unix.py"\
        "\n    -c|--crash_bin             File to record crash info too" \
        "\n    [-P|--port PORT]             TCP port to bind this agent too"\
        "\n    [-l|--log_level LEVEL]       log level (default 1), increase for more verbosity"

ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or os._exit(1)

servlet = None

class debugger_thread(threading.Thread):
    global servlet
    def __init__(self, procmon_options):
        '''
        '''
        super(debugger_thread,self).__init__()

        self.procmon_options = procmon_options
        self.pid = None
        self.readBuff = ""
        self.gdbActive = False
        self.c_str = "(gdb)"
        self.crash = False

        self.wrPipe = [0,0]
        self.rdPipe = [0,0]
        self.errPipe = [0,0]

        try:
            self.wrPipe[0],self.wrPipe[1] = os.pipe()
            self.rdPipe[0],self.rdPipe[1] = os.pipe()
            self.errPipe[0],self.errPipe[1] = os.pipe()
        except:
            print "Create pip failed"
            os._exit(0)
        
    def start_monitoring(self):
        '''
        '''

        os.close(self.rdPipe[0])
        os.close(self.wrPipe[1])
        os.close(self.errPipe[0])
        os.dup2(self.rdPipe[1],sys.stdout.fileno())
        os.dup2(self.wrPipe[0],sys.stdin.fileno())
        os.dup2(self.errPipe[1],sys.stderr.fileno())

        os.execv(self.procmon_options["gdb_path"],[self.procmon_options["debug_file"]])

    def write_to_gdb(self,cmd=""):
        if len(cmd) > 0 and cmd[len(cmd)-1]!='\n':
            cmd += "\n"

        try:
            os.write(self.wrPipe[1],cmd)
        except:
            print "write pipe failed"
            raise Exception

    def run(self):
        timestamp = time.time()
        self.pid = os.fork()
        if self.pid == 0:
            #subproc
            self.start_monitoring()
            os._exit(0)

        os.close(self.wrPipe[0])
        os.close(self.rdPipe[1])
        os.close(self.errPipe[1])

        try:
            if len(self.procmon_options["debug_file"]) > 0:
                cmd = "file %s" % self.procmon_options["debug_file"]
                self.write_to_gdb(cmd)

            for cmd in self.procmon_options["gdb_cmd"]:
                self.write_to_gdb(cmd)

            if len(self.procmon_options["proc_args"]) > 0:
                cmd = "set args %s" % self.procmon_options["proc_args"]
                self.write_to_gdb(cmd)
        except:
            print "Set gdb cmd failed"
            os._exit(0)

        while True:
            rdSet = [self.rdPipe[0],self.errPipe[0]]
            rdList,wrList,errList = select.select(rdSet,[],[],0.001)
            for r in rdList:
                if r is self.rdPipe[0]:
                    try:
                        self.readBuff = os.read(r,1024)
                        if len(self.readBuff) == 0:
                            continue

                        if not self.crash and self.gdbActive:
                            try:
                                self.readBuff.index(self.c_str)
                                self.crash = True
                                for cmd in self.procmon_options["crash_cmd"]:
                                    self.write_to_gdb(cmd)
                            except:
                                pass

                        if self.crash:
                            servlet.report_crash(self.readBuff)
                            timestamp = time.time()

                        print self.readBuff

                    except:
                        continue

                elif r is self.errPipe[0]:
                    try:
                        self.readBuff = os.read(r, 1024)
                        if len(self.readBuff) == 0:
                            continue

                        print self.readBuff
                    except:
                        continue

            if self.crash and (time.time() - timestamp > 2):
                servlet.report_EOF = True




########################################################################################################################

class nix_process_monitor_pedrpc_server(pedrpc.server):
    def __init__(self, host, port, crash_bin, log_level=1):
        '''
        @type host: String
        @param host: Hostname or IP address
        @type port: Integer
        @param port: Port to bind server to
        @type crash_bin: String
        @param crash_bin: Where to save monitored process crashes for analysis
        
        '''
        
        pedrpc.server.__init__(self, host, port)
        self.crash_bin = crash_bin
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

    ####################################################################################################################
    def report_crash(self,report):
        self.crashReport += report

    def serve_forever (self):
        while 1:
            try:
                self._disconnect()
                (self._client_sock, self._client_address) = self._server.accept()
                self._debug("accepted connection from %s:%d" % (self._client_address[0], self._client_address[1]))
            except:
                print "accept socket failed"
                continue

            while True:
                self.recvData = None
                try:
                    self.recvData = self._ex_recv()
                    #print "recv proto:",self.recvData.protoName
                except:
                    print "recv exception"
                    break

                if self.recvData.protoName == "Debug_Options":
                    try:
                        self.procmon_options = self.recvData.procmonOptions
                        #print self.procmon_options
                        self.debug_thread = debugger_thread(self.procmon_options)   #create debug thread
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

                elif self.recvData.protoName == "Request_Report":
                    time.sleep(self.procmon_options["report_spacing"])
                    if self.debug_thread.crash:
                        while not self.report_EOF:
                            time.sleep(0.1)
                        debugReport = protocol.Debug_Report(crash=True, report=self.crashReport)
                        self._ex_send(debugReport)
                        os._exit(0)
                    else:
                        debugReport = protocol.Debug_Report(False)
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

def sigint_handler(sig,frame):
    print "recv sigint"
    os._exit(0)

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:P:l:", ["crash_bin=","port=","log_level=",])
    except getopt.GetoptError:
        ERR(USAGE)

    log_level = 1
    PORT = None
    crash_bin = None
    for opt, arg in opts:
        if opt in ("-c", "--crash_bin"):   crash_bin  = arg
        if opt in ("-P", "--port"): PORT = int(arg)
        if opt in ("-l", "--log_level"):   log_level  = int(arg)

    #if not crash_bin: ERR(USAGE)
    
    if PORT == None:
        PORT = 7502
    signal.signal(signal.SIGINT,sigint_handler)
    # spawn the PED-RPC servlet.

    servlet = nix_process_monitor_pedrpc_server("0.0.0.0", PORT, crash_bin, log_level)
    servlet.serve_forever()

