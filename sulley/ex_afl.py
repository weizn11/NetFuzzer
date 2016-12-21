# -*- coding:utf-8 -*-
import os
import sys
import ipc
import signal

try:
    import afl
except:
    print "[ERROR] 无法加载\"afl\"模块,请输入以下命令安装:\nsudo apt-get install python-afl"
    os._exit(-1)

try:
    import psutil
except:
    print "[ERROR] 无法加载\"psutil\"模块,请输入以下命令安装:\npip install psutil"
    os._exit(-1)

##############################################################################
def dump_corpus_file(dir, block):
    '''
    :desc: 将用户定义的数据类型dump到语料库中
    :type dir: String
    :param dir: 语料库目录路径
    :type block: blocks.request()
    :param block: 用户规定的Fuzz数据类型
    :return: 1.True:语料库文件创建成功  2.语料库文件创建失败
    '''

    fileName = block.get_name()
    try:
        if not os.path.exists(dir):
            os.mkdir(dir)
    except Exception, e:
        print "[ERROR] Create '%s' directory error. Exception: %s" % (dir, str(e))
        return False

    try:
        payload = block.render()
        file = open(dir + "/" + fileName, "w")
        file.write(payload)
        file.close()
    except Exception, e:
        print "[ERROR] Can't write file into corpus. Exception: %s" % str(e)
        return False

    return True

##############################################################################
def remove_corpus(dir):
    '''
    :desc: 删除已创建的语料库
    :type dir: String
    :param dir: 语料库目录路径
    :return: (boolean)
    '''

    try:
        if not os.path.exists(dir):
            os.system("rm -rf " + dir)
    except Exception, e:
        print "[ERROR] Remove '%s' directory error. Exception: %s" % (dir, str(e))
        return False
    return True

##############################################################################
class AFL(object):
    needDelTmp = True
    def __init__(self, name, corpusDir):
        self.name = name
        self.corpusDir = os.getcwd() + "/" + corpusDir
        self.wrPipe = None
        self.rdPipe = None
        self.AFLpid = None
        self.aflPath = "/usr/bin/py-afl-fuzz"
        self.pythonPath = "/usr/bin/python"

        self.curMutateData = None
        self.mutateSymbol = None
        self.mutateLength = None

        self.startFlag = False

        if not os.path.exists(self.aflPath):
            print "[ERROR] Not found '%s'." % self.aflPath
            os._exit(-1)
        if not os.path.exists(self.pythonPath):
            print "[ERROR] Not found '%s'." % self.pythonPath
            os._exit(-1)

        try:
            self.name.index(":")
            raise Exception("[ERROR] Can't appear ':'")
        except:
            return

    #################################################################################
    def start_afl_fuzz(self):
        if self.startFlag:
            print "[INFO] The afl-fuzz process is already started."
            return True
        #Init
        if AFL.needDelTmp:
            #delete old conf file
            if os.path.exists(".tmp_aflConf"):
                try:
                    os.remove(".tmp_aflConf")
                except Exception, e:
                    print "[ERROR] Remove file '.tmp_aflConf' error. Exception: %s" % str(e)
                    return False

            # delete debug log
            if os.path.exists("debug.txt"):
                os.remove("debug.txt")

            # patch core_pattern
            os.system("echo core >/proc/sys/kernel/core_pattern")

            AFL.needDelTmp = False
        else:
            try:
                file = open(".tmp_aflConf", "r")
            except Exception, e:
                print "[ERROR] Open file '.tmp_aflConf' error. Exception: %s" % str(e)
                return False
            try:
                lineList = file.readlines()
                file.close()
            except Exception, e:
                print "[ERROR] readlines error. Exception: %s" % str(e)
                file.close()
                return False
            try:
                for line in lineList:
                    if line[-1] == '\n':
                        line = line[:-1]
                    wordList = line.split(":")

                    if wordList[1] == self.name:
                        print "[ERROR] The '%s' object name already exists." % self.name
                        return False
            except Exception, e:
                print "[ERROR] Parse file error. Exception: %s" % str(e)
                return False

        #delete output directory
        if os.path.exists("out_" + self.name):
            os.system("rm -rf " + "out_" + self.name)
            os.system("mkdir " + "out_" + self.name)

        #delete log file
        if os.path.exists("log_%s.txt" % self.name):
            os.remove("log_%s.txt" % self.name)

        #check input directory
        if not os.path.exists(self.corpusDir):
            print "[ERROR] The '%s' directory does not seem to be valid." % self.corpusDir
            os._exit(0)

        #start py-afl-fuzz subprocess
        self.AFLpid = os.fork()
        if self.AFLpid == 0:
            nul = os.open("/dev/null", os.O_ASYNC | os.O_WRONLY)
            os.dup2(nul, sys.stdout.fileno())
            os.dup2(nul, sys.stdin.fileno())

            try:
                os.execl(self.aflPath, self.aflPath, "-n", "-t", "999999", "-i", self.corpusDir,
                         "-o", "out_" + self.name, "--", self.pythonPath, os.getcwd() + "/sulley/AFLInterface.py", "@@")
            except Exception, e:
                print "[ERROR] Start 'py-afl-fuzz' failed. Exception: %s" % str(e)
            finally:
                pass
                #os._exit(0)
        if self.AFLpid < 0:
            print "[ERROR] Start 'py-afl-fuzz' process failed."
            return False

        #write afl conf into file
        aflInfoFile = open(".tmp_aflConf", "a")
        aflInfoFile.write("%d:%s:.tmp_a2sPipe_%s:log_%s\n" % (self.AFLpid, self.name, self.name, self.name))
        aflInfoFile.close()

        if ipc.create_fifo_pipe(".tmp_a2sPipe_%s" % self.name) is False:
            return False

        self.rdPipe = ipc.open_rd_fifo_pipe(".tmp_a2sPipe_%s" % self.name)
        if self.rdPipe is None:
            return False
        self.startFlag = True

        return True

    #################################################################################
    def fetch_fuzz_payload(self, symbol=None, length=None):
        if not self.startFlag:
            return None
        while True:
            payload = ipc.pipe_recv(self.rdPipe)
            if payload is None or len(payload) < 1:
                continue
            if symbol is None or length is None:
                return payload

            if symbol == "==":
                if len(payload) >= length:
                    return payload[:length]
            elif symbol == ">=":
                if len(payload) >= length:
                    return payload
            elif symbol == "<=":
                if len(payload) <= length:
                    return payload
            elif symbol == ">":
                if len(payload) > length:
                    return payload
            elif symbol == "<":
                if len(payload) < length:
                    return payload
            elif symbol == "!=" or symbol == "<>":
                if len(payload) != length:
                    return payload
            else:
                return payload

    #################################################################################
    def set_mutate_option(self, symbol, length):
        self.mutateSymbol = symbol
        self.mutateLength = length
        return

    def set_mutate_payload(self, payload):
        self.curMutateData = payload
        return

    def mutate(self):
        if self.startFlag is False:
            try:
                if self.start_afl_fuzz() is False:
                    return False
            except Exception, e:
                print "start_afl_fuzz() error. Exception: %s" % str(e)
                return False
        self.curMutateData = self.fetch_fuzz_payload(self.mutateSymbol, self.mutateLength)
        if self.curMutateData is None:
            return False
        return True

    def render(self):
        return self.curMutateData

    #################################################################################
    def stop_afl_fuzz(self):
        self.startFlag = False
        if self.AFLpid is None:
            return 0
        (exiPid, exiVal) = (None, None)
        try:
            os.kill(self.AFLpid, signal.SIGKILL)
            (exiPid, exiVal) = os.wait()
        except Exception, e:
            print "[ERROR] Stop afl_fuzz failed. Exception: %s" % str(e)

        print "[INFO] Subprocess '%d' finished with exit code %d." % (exiPid, exiVal)
        return exiPid

##############################################################################
'''
afl_test = AFL("test", "in")
afl_test_2 = AFL("test2", "in2")
if afl_test.start_afl_fuzz():
    print "afl start successful"
else:
    print "afl start failed."
    os._exit(-1)

if afl_test_2.start_afl_fuzz():
    print "afl start successful"
else:
    print "afl start failed."
    os._exit(-1)

import time
count = 0
time.sleep(5)
while True:
    count += 1

    payload = afl_test.fetch_fuzz_payload("!=", 10)
    if payload is None:
        os._exit(0)
    print "\ncounts is %d, payload: %s" % (count, payload)


    payload = afl_test_2.fetch_fuzz_payload("<=", 5)
    if payload is None:
        os._exit(0)
    print "\ncounts is %d, payload: %s" % (count, payload)


    if count > 100000:
        break
    #time.sleep(1)

afl_test.stop_afl_fuzz()
afl_test_2.stop_afl_fuzz()
'''




