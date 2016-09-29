# -*- coding:utf-8 -*-
import sys
import struct
import os
import socket
import cPickle
import protocol

########################################################################################################################
class client:
    def __init__ (self, host, port=7437):
        self._host           = host
        self._port           = port
        self._dbg_flag       = False
        self._server_sock    = None
        self._retry          = 0
        self.NOLINGER         = struct.pack('ii', 1, 0)


    ####################################################################################################################
    def connect (self):
        '''
        Connect to the server.
        '''

        # if we have a pre-existing server socket, ensure it's closed.
        self.disconnect()

        # connect to the server, timeout on failure.
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.settimeout(3.0)
            self._server_sock.connect((self._host, self._port))
        except:
            print "Connect to proc monitor failed"
            os._exit(0)

        # disable timeouts and lingering.
        self._server_sock.settimeout(None)
        print "Connect to proc monitor success"
        #self.__server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, self.NOLINGER)

    ####################################################################################################################
    def disconnect (self):
        '''
        Ensure the socket is torn down.
        '''

        if self._server_sock != None:
            self._debug("closing server socket")
            self._server_sock.close()
            self._server_sock = None

    ####################################################################################################################
    def _debug (self, msg):
        print "PED-RPC> %s" % msg

    ####################################################################################################################
    def ex_recv(self):
        '''
        '''

        recvLength = 4
        nextLength = 0

        try:
            while recvLength:
                nextLength = self._server_sock.recv(recvLength)
                recvLength -= len(nextLength)
        except Exception, e:
            print "recv() error at step 1.\nTrace info:"
            print e
            raise Exception

        recvLength = struct.unpack("<i", nextLength)[0]
        try:
            data = ""
            while recvLength:
                chunk = self._server_sock.recv(recvLength)
                data += chunk
                recvLength -= len(data)
        except Exception, e:
            print "recv() error at step 2.\nTrace info:"
            print e
            raise Exception

        hdr = cPickle.loads(data)
        recvLength = hdr.nextLength
        try:
            data = ""
            while recvLength:
                chunk = self._server_sock.recv(recvLength)
                data += chunk
                recvLength -= len(data)
        except Exception, e:
            print "recv() error at step 3.\nTrace info:"
            print e
            raise Exception

        objData = cPickle.loads(data)

        return objData

    ####################################################################################################################
    def ex_send(self, data):
        '''
        @param data:    发送的数据
        @return:    无返回值，出错将抛出异常
        '''

        #序列化数据包
        serData = cPickle.dumps(data, protocol=2)
        hdr = protocol.Header(nextProtoName=data.protoName, nextLength=len(serData))
        serHdr = cPickle.dumps(hdr, protocol=2)

        try:
            self._server_sock.send(struct.pack("<i", len(serHdr)))
            self._server_sock.send(serHdr)
            self._server_sock.send(serData)
        except:
            print "send error!"
            raise Exception

    ####################################################################################################################
    def fetch_procmon_status(self):
        '''
        @desc:  获取进程crash报告
        @return: (boolean, String) 若进程crash则返回True，并返回crash报告。
        '''

        retVal = False
        crashReport = ""
        recvReport = None

        requestReport = protocol.Fetch_Report()
        try:
            self.ex_send(requestReport)
        except Exception, e:
            print "fetch_procmon_status send exception.\nTrace info:"
            print e
            os._exit(0)
            return retVal, None

        try:
            recvReport = self.ex_recv()
        except Exception, e:
            print "fetch_procmon_status recv exception.\nTrace info:"
            print e
            os._exit(0)
            return retVal, crashReport

        retVal = recvReport.crash
        if retVal:
            #procmon crash
            crashReport += recvReport.report
            retVal = True
            return retVal, crashReport
        else:
            return retVal, None

########################################################################################################################
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
        hdr = protocol.Header(nextProtoName=data.protoName,nextLength=len(serData))
        serHdr = cPickle.dumps(hdr,protocol=2)

        try:
            self._client_sock.send(struct.pack("<i",len(serHdr)))
            self._client_sock.send(serHdr)
            self._client_sock.send(serData)
        except:
            print "send error!"
            raise Exception


