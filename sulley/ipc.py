# -*- coding:utf-8 -*-
import os
import struct

def open_rd_fifo_pipe(rdPipePath):
    rdPipe = None

    try:
        rdPipe = open(rdPipePath, "r")
    except Exception, e:
        print "Open read fifo failed. Exception: %s" % e
    finally:
        return rdPipe

############################################################################
def open_wr_fifo_pipe(wrPipePath):
    wrPipe = None

    try:
        wrPipe = os.open(wrPipePath, os.O_WRONLY)
    except Exception, e:
        print "Open write fifo failed. Exception: %s" % e
    finally:
        return wrPipe

############################################################################
def close_rd_fifo_pipe(rdPipe):
    if rdPipe is None:
        return True
    try:
        rdPipe.close()
    except Exception, e:
        print "Close read pipe failed. Exception: %s" % e
        return False
    return True

############################################################################
def close_wr_fifo_pipe(wrPipe):
    if wrPipe is None:
        return True
    try:
        os.close(wrPipe)
    except Exception, e:
        print "Close write pipe failed. Exception: %s" % e
        return False
    return True

############################################################################
def pipe_recv(rdPipe):
    totalLength = 4
    recvHdr = True
    recvBuf = ""

    while True:
        try:
            chunk = rdPipe.read(totalLength)
            if len(chunk) == 0:
                return None
            recvBuf += chunk
            totalLength -= len(chunk)
        except Exception, e:
            print "Read fifo failed. Exception: %s" % e
            return None

        if totalLength == 0:
            if recvHdr:
                totalLength = struct.unpack("<i", recvBuf)[0]
                recvHdr = False
                recvBuf = ""
            else:
                return recvBuf

############################################################################
def pipe_send(wrPipe, rawData):
    if rawData is None or len(rawData) < 1:
        return True
    rawData = struct.pack("<i", len(rawData)) + rawData
    while rawData is not None:
        if len(rawData) > 4096:
            sendData = rawData[:4096]
            rawData = rawData[4096:]
        else:
            sendData = rawData
            rawData = None
        try:
            os.write(wrPipe, sendData)
        except Exception, e:
            print "Write pipe failed. Exception: %s" % e
            return False
    return True

############################################################################
def create_fifo_pipe(pipePath):
    try:
        if os.path.exists(pipePath):
            os.remove(pipePath)
        os.mkfifo(pipePath, 0644)
    except Exception, e:
        print "mkfifo failed. Exception: %s" % e
        return False

    return True






