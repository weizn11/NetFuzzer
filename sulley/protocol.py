class Header:
    def __init__(self,nextProtoName="", nextLength=0):
        self.nextProtoName = nextProtoName
        self.nextLength = nextLength

class Debug_Options:
    def __init__(self, procmonOptions={}):
        self.protoName = "Debug_Options"
        self.procmonOptions = procmonOptions

class Debug_Report:
    def __init__(self, crash=False, report=""):
        self.protoName = "Debug_Report"
        self.crash = crash
        self.report = report

class Debug_Cmd:
    def __init__(self, cmd=""):
        self.protoName = "Debug_Cmd"
        self.cmd = cmd

class Fetch_Report:
    def __init__(self):
        self.protoName = "Fetch_Report"