##  BASED ON:
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

from .utils.logger import *
from .loaders.elf import *
from .loaders.pe import *
from binascii import unhexlify


class Binary(object):
    def __init__(self, filename):
        self.__filename = filename
        self.__rawBinary = None
        self.__binary = None

        try:
            fd = open(self.__filename, "rb")
            self.__rawBinary = fd.read()
            fd.close()
        except Exception:
            log_error("Unable to open the binary '%s'" % filename)
            return None

        if self.__rawBinary[:4] == unhexlify(b"7f454c46"):
            self.__binary = ELF(self.__rawBinary)
        elif self.__rawBinary[:2] == unhexlify(b"4d5a"):
            self.__binary = PE(self.__rawBinary)
        else:
            log_error("Binary format not supported. ELF and PE are the supported formats")
            return None

    def getFileName(self):
        return self.__filename

    def getRawBinary(self):
        return self.__rawBinary

    def getBinary(self):
        return self.__binary

    def getEntryPoint(self):
        return self.__binary.getEntryPoint()

    def getDataSections(self):
        return self.__binary.getDataSections()

    def getExecSections(self):
        return self.__binary.getExecSections()

    def getArch(self):
        return self.__binary.getArch()

    def getArchMode(self):
        return self.__binary.getArchMode()

    def getFormat(self):
        return self.__binary.getFormat()
