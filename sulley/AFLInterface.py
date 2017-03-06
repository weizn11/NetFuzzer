# -*- coding:utf-8 -*-
import os
import sys
import signal
import ipc
import time
import afl
import psutil

##############################################################################
pipeName = None
logName = None
pipeAlive = False
rdPipe, wrPipe = None, None

##############################################################################
def logger(str):
    global logName
    try:
        file = open(logName + ".txt", "a")
        file.write(str + "\n")
        file.close()
    except:
        return

def debug(str):
    '''
    file = open("debug.txt", "a")
    file.write(str + "\n")
    file.close()
    '''
    return

##############################################################################
def read_afl_conf():
    global pipeName
    global logName

    try:
        file = open(".tmp_aflConf", "r")
    except Exception, e:
        debug("Open file '.tmp_aflConf' error. Exception: %s" % str(e))
        return False
    try:
        lineList = file.readlines()
        file.close()
    except Exception, e:
        debug("readlines error. Exception: %s" % str(e))
        file.close()
        return False

    pProc = psutil.Process(os.getppid())
    try:
        for line in lineList:
            if line[-1] == '\n':
                line = line[:-1]
            wordList = line.split(":")

            debug(wordList[0] + "\t" + str(pProc.ppid()))
            if int(wordList[0]) == pProc.ppid():
                pipeName = wordList[2]
                logName = wordList[3]
                return True
    except Exception, e:
        debug("Parse file error. Exception: %s" % str(e))
        return False

    return False

##############################################################################
def open_pipe():
    global pipeName
    global pipeAlive
    global rdPipe, wrPipe

    #wait for parent create pipe
    time.sleep(1)

    #read from afl conf file
    if read_afl_conf() is False:
        debug("read_afl_conf error")
        return False
    else:
        debug("read_afl_conf success")

    #open write pipe
    wrPipe = ipc.open_wr_fifo_pipe(pipeName)
    if wrPipe is None:
        logger("Open write pipe error.")
        return False
    else:
        logger("Open write pipe successful.")

    pipeAlive = True
    return True

##############################################################################
#start at here
while afl.loop(99999999):
    #open write pipe
    if pipeAlive is False:
        if open_pipe() is False:
            os.kill(0 - os.getppid(), signal.SIGKILL)
            os.kill(0 - os.getpid(), signal.SIGKILL)
        else:
            pipeAlive = True

    #read from input file
    try:
        input = open(sys.argv[1], "r")
        payload = ""
        while True:
            try:
                chunk = input.read(65535)
                if len(chunk) < 1:
                    break
                payload += chunk
            except:
                break
        input.close()
    except Exception, e:
        logger("Read input file failed. Exception: %s" % e)
        continue

    #send fuzz case
    #logger("Send fuzz case length: %d" % (len(payload)))
    if ipc.pipe_send(wrPipe, payload) is False:
        logger("Send fuzz case failed. The 'py-afl-fuzz' process will exit.")
        os.kill(0 - os.getppid(), signal.SIGKILL)
        os.kill(0 - os.getpid(), signal.SIGKILL)

##############################################################################
logger("Break loop.")
if ipc.close_wr_fifo_pipe(wrPipe):
    logger("The write pipe closed successful.")
else:
    logger("The write pipe closed failed.")
pipeAlive = False









